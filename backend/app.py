import os
from flask import Flask, jsonify, request, g
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
import re
from neo4j import GraphDatabase
from dotenv import load_dotenv

try:
    from flask_cors import CORS
except ImportError:
    CORS = None

load_dotenv()
app = Flask(__name__)
if CORS:
    CORS(app)

driver = GraphDatabase.driver(
    os.getenv("NEO4J_URI", "neo4j://127.0.0.1:7687"),
    auth=(os.getenv("NEO4J_USER", "neo4j"), os.getenv("NEO4J_PASSWORD", "")),
)

TEST_PATIENT_MIN = 307      # patients added through the app
TEST_APPT_MIN = 5000        # appointments added through the app
GROUPS = ["Patient", "Doctor", "Department", "Disease", "Appointment",
          "LabTest", "Prescription", "Medicine", "Bill"]


def q(query, **params):
    with driver.session() as s:
        return [r.data() for r in s.run(query, **params)]


def bad(msg, code=400):
    return jsonify({"error": msg}), code
# =========================================================
# PATIENT AUTHENTICATION
# =========================================================

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is missing. Add it to your backend/.env file."
    )

token_serializer = URLSafeTimedSerializer(
    SECRET_KEY,
    salt="medigraph-patient-auth"
)

TOKEN_EXPIRY = 7 * 24 * 60 * 60  # 7 days


def create_patient_token(patient_id):
    return token_serializer.dumps({
        "patient_id": patient_id,
        "role": "patient"
    })


def patient_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return bad("Please log in to continue", 401)

        token = auth_header.split(" ", 1)[1].strip()

        try:
            payload = token_serializer.loads(
                token,
                max_age=TOKEN_EXPIRY
            )

            if payload.get("role") != "patient":
                return bad("Invalid account type", 401)

            g.patient_id = int(payload["patient_id"])

        except SignatureExpired:
            return bad("Your session has expired. Please log in again.", 401)

        except (BadSignature, KeyError, TypeError, ValueError):
            return bad("Invalid login session", 401)

        return func(*args, **kwargs)

    return wrapper


# ---------- graph helpers ----------
def group_of(n):
    for g in GROUPS:
        if g in n.labels:
            return g
    return next(iter(n.labels), "Node")


def caption(n):
    for k in ("name", "disease_name", "test_name", "dept_name"):
        if k in n:
            return str(n[k])
    for k in ("appointment_id", "prescription_id", "bill_id"):
        if k in n:
            return f"{group_of(n)} {n[k]}"
    return group_of(n)


def paths_to_graph(query, **params):
    nodes, edges = {}, {}
    with driver.session() as s:
        for rec in s.run(query, **params):
            for v in rec.values():
                if hasattr(v, "nodes"):
                    for n in v.nodes:
                        nodes[n.element_id] = n
                    for r in v.relationships:
                        edges[r.element_id] = r
    return jsonify({
        "nodes": [{"id": i, "label": caption(n), "group": group_of(n),
                   "props": {k: str(v) for k, v in dict(n).items()}}
                  for i, n in nodes.items()],
        "edges": [{"id": i, "from": r.start_node.element_id,
                   "to": r.end_node.element_id, "label": r.type}
                  for i, r in edges.items()],
    })


# ---------- basic ----------
@app.get("/api/health")
def health():
    q("RETURN 1 AS ok")
    return jsonify({"status": "ok"})


@app.get("/api/stats")
def stats():
    nodes = q("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS total ORDER BY label")
    rels = q("MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS total ORDER BY type")
    return jsonify({
        "nodes": nodes, "relationships": rels,
        "total_nodes": sum(n["total"] for n in nodes),
        "total_relationships": sum(r["total"] for r in rels),
    })


@app.get("/api/patients")
def patients():
    return jsonify(q("""
        MATCH (p:Patient)
        RETURN p.patient_id AS id, p.name AS name, p.gender AS gender,
               toString(p.dob) AS dob ORDER BY p.patient_id"""))


@app.get("/api/doctors")
def doctors():
    return jsonify(q("""
        MATCH (d:Doctor)-[:WORKS_IN]->(dep:Department)
        RETURN d.doctor_id AS id, d.name AS name, d.specialization AS specialization,
               dep.dept_name AS department, coalesce(d.type, '') AS type
        ORDER BY department, name"""))


@app.get("/api/medicines")
def medicines():
    return jsonify(q("""
        MATCH (m:Medicine)
        RETURN m.name AS name, m.price AS price,
               coalesce(m.manufacturer, '') AS manufacturer ORDER BY m.name"""))


@app.get("/api/diseases")
def diseases():
    return jsonify(q("""
        MATCH (d:Disease)
        RETURN d.disease_id AS id, d.disease_name AS name ORDER BY id"""))


# ---------- graph views ----------
@app.get("/api/graph")
def graph_all():
    return paths_to_graph("MATCH p=(a)-[r]->(b) RETURN p")


@app.get("/api/graph/patient/<int:pid>")
def graph_patient(pid):
    return paths_to_graph(
        "MATCH path=(p:Patient {patient_id:$id})-[*1..4]->(x) RETURN path", id=pid)


@app.get("/api/graph/doctor/<int:did>")
def graph_doctor(did):
    return paths_to_graph("""
        MATCH path=(d:Doctor {doctor_id:$id})-[:WORKS_IN]->(:Department) RETURN path
        UNION
        MATCH path=(d:Doctor {doctor_id:$id})<-[:WITH_DOCTOR]-(:Appointment)<-[:BOOKED]-(:Patient)
        RETURN path""", id=did)


@app.get("/api/graph/shared-disease")
def graph_shared():
    return paths_to_graph("""
        MATCH path=(p1:Patient)-[:DIAGNOSED_WITH]->(d:Disease)<-[:DIAGNOSED_WITH]-(p2:Patient)
        WHERE p1.patient_id < p2.patient_id RETURN path""")


@app.get("/api/graph/medicine-together")
def graph_together():
    name = request.args.get("name", "")
    return paths_to_graph("""
        MATCH path=(:Medicine {name:$n})<-[:CONTAINS]-(:Prescription)-[:CONTAINS]->(:Medicine)
        RETURN path""", n=name)


@app.get("/api/graph/shortest-path")
def graph_path():
    try:
        a, b = int(request.args["from"]), int(request.args["to"])
    except (KeyError, ValueError):
        return bad("Choose two patients")
    if a == b:
        return bad("Pick two different patients")
    return paths_to_graph("""
        MATCH (a:Patient {patient_id:$a}), (b:Patient {patient_id:$b})
        MATCH path = shortestPath((a)-[*]-(b)) RETURN path""", a=a, b=b)


# ---------- analytics ----------
@app.get("/api/revenue")
def revenue():
    return jsonify(q("""
        MATCH (d:Doctor)<-[:WITH_DOCTOR]-(:Appointment)-[:HAS_PRESCRIPTION]->
              (:Prescription)-[:BILLED_AS]->(b:Bill)
        RETURN d.name AS doctor, sum(b.consultation_charge + b.medicine_charge) AS revenue
        ORDER BY revenue DESC"""))


@app.get("/api/shared-disease")
def shared_disease():
    return jsonify(q("""
        MATCH (p1:Patient)-[:DIAGNOSED_WITH]->(d:Disease)<-[:DIAGNOSED_WITH]-(p2:Patient)
        WHERE p1.patient_id < p2.patient_id
        RETURN p1.name AS patient1, p2.name AS patient2, d.disease_name AS disease"""))


@app.get("/api/medicines/together")
def medicines_together():
    name = request.args.get("name", "")
    return jsonify(q("""
        MATCH (:Medicine {name:$n})<-[:CONTAINS]-(:Prescription)-[:CONTAINS]->(m:Medicine)
        WHERE m.name <> $n
        RETURN m.name AS also_prescribed, count(*) AS times ORDER BY times DESC""", n=name))


@app.get("/api/patient-summary/<int:bill_id>")
def patient_summary(bill_id):
    rows = q("""
        MATCH (p:Patient)-[:BOOKED]->(a:Appointment)-[:WITH_DOCTOR]->(d:Doctor),
              (a)-[:HAS_PRESCRIPTION]->(:Prescription)-[:BILLED_AS]->(b:Bill {bill_id:$id})
        OPTIONAL MATCH (p)-[:DIAGNOSED_WITH]->(dis:Disease)
        RETURN p.name AS patient, d.name AS doctor,
               collect(DISTINCT dis.disease_name) AS diagnosis,
               b.consultation_charge + b.medicine_charge AS total_bill""", id=bill_id)
    if not rows:
        return bad("No bill with that ID", 404)
    for r in rows:
        r["diagnosis"] = ", ".join(r["diagnosis"]) or "none"
    return jsonify(rows)


# ---------- patient profile ----------
@app.get("/api/patients/<int:pid>/detail")
def patient_detail(pid):
    p = q("""
        MATCH (p:Patient {patient_id:$id})
        RETURN p.patient_id AS id, p.name AS name, p.gender AS gender,
               toString(p.dob) AS dob""", id=pid)
    if not p:
        return bad("Patient not found", 404)
    diseases_ = q("""
        MATCH (:Patient {patient_id:$id})-[:DIAGNOSED_WITH]->(d:Disease)
        RETURN d.disease_name AS name, d.description AS description""", id=pid)
    visits = q("""
        MATCH (:Patient {patient_id:$id})-[:BOOKED]->(a:Appointment)
              -[:WITH_DOCTOR]->(d:Doctor)-[:WORKS_IN]->(dep:Department)
        OPTIONAL MATCH (a)-[:HAS_TEST]->(t:LabTest)
        OPTIONAL MATCH (a)-[:HAS_PRESCRIPTION]->(pr:Prescription)
        OPTIONAL MATCH (pr)-[:CONTAINS]->(m:Medicine)
        OPTIONAL MATCH (pr)-[:BILLED_AS]->(b:Bill)
        RETURN a.appointment_id AS appointment, d.name AS doctor,
               d.specialization AS specialization, dep.dept_name AS department,
               collect(DISTINCT {name:t.test_name, cost:t.cost, result:t.result}) AS tests,
               toString(pr.prescription_date) AS prescription_date,
               collect(DISTINCT {name:m.name, price:m.price}) AS medicines,
               b.consultation_charge AS consultation, b.medicine_charge AS medicine_charge
        ORDER BY a.appointment_id""", id=pid)
    return jsonify({"patient": p[0], "diseases": diseases_, "visits": visits})


# ---------- add / delete ----------
@app.post("/api/patients")
def add_patient():
    d = request.get_json(force=True)
    try:
        pid = int(d.get("patient_id"))
    except (TypeError, ValueError):
        return bad("Enter a numeric patient ID")
    name = (d.get("name") or "").strip()
    if not name:
        return bad("Enter a name")
    if not d.get("dob"):
        return bad("Choose a date of birth")
    if pid < TEST_PATIENT_MIN:
        return bad(f"Use a patient ID of {TEST_PATIENT_MIN} or higher")
    if q("MATCH (p:Patient {patient_id:$id}) RETURN p", id=pid):
        return bad("That patient ID already exists")
    q("CREATE (:Patient {patient_id:$id, name:$n, dob:date($dob), gender:$g})",
      id=pid, n=name, dob=d["dob"], g=d.get("gender", "Male"))
    dis = d.get("disease_id")
    if dis and str(dis) != "none":
        q("""MATCH (p:Patient {patient_id:$id}), (x:Disease {disease_id:$dis})
             CREATE (p)-[:DIAGNOSED_WITH]->(x)""", id=pid, dis=int(dis))
    return jsonify({"message": f"Added patient {name}"})


@app.post("/api/appointments")
def add_appointment():
    d = request.get_json(force=True)
    try:
        pid, did = int(d["patient_id"]), int(d["doctor_id"])
    except (KeyError, TypeError, ValueError):
        return bad("Choose a patient and a doctor")
    top = q("MATCH (a:Appointment) RETURN max(a.appointment_id) AS m")[0]["m"] or 0
    new_id = max(top, TEST_APPT_MIN - 1) + 1
    res = q("""
        MATCH (p:Patient {patient_id:$p}), (d:Doctor {doctor_id:$d})
        CREATE (p)-[:BOOKED]->(a:Appointment {appointment_id:$a})-[:WITH_DOCTOR]->(d)
        RETURN a.appointment_id AS id""", p=pid, d=did, a=new_id)
    if not res:
        return bad("Patient or doctor not found", 404)
    return jsonify({"message": "Appointment booked", "appointment_id": new_id})


@app.get("/api/test-data")
def test_data():
    pts = q("""MATCH (p:Patient) WHERE p.patient_id >= $m
               RETURN p.patient_id AS id, p.name AS name ORDER BY id""", m=TEST_PATIENT_MIN)
    appts = q("""MATCH (p:Patient)-[:BOOKED]->(a:Appointment)-[:WITH_DOCTOR]->(d:Doctor)
                 WHERE a.appointment_id >= $m
                 RETURN a.appointment_id AS id, p.name AS patient, d.name AS doctor
                 ORDER BY id""", m=TEST_APPT_MIN)
    return jsonify({"patients": pts, "appointments": appts})


@app.delete("/api/patients/<int:pid>")
def delete_patient(pid):
    if pid < TEST_PATIENT_MIN:
        return bad("Original data cannot be deleted", 403)
    q("MATCH (p:Patient {patient_id:$id}) DETACH DELETE p", id=pid)
    return jsonify({"message": "Patient deleted"})


@app.delete("/api/appointments/<int:aid>")
def delete_appointment(aid):
    if aid < TEST_APPT_MIN:
        return bad("Original data cannot be deleted", 403)
    q("MATCH (a:Appointment {appointment_id:$id}) DETACH DELETE a", id=aid)
    return jsonify({"message": "Appointment deleted"})



# =====================================================================
# NEW ROUTES FOR THE FULL HOSPITAL WEBSITE  (paste above __main__)
# =====================================================================
APP_FLOOR = 1000   # IDs of doctors, prescriptions, bills, diseases created in the app


def next_id(label, prop, floor=APP_FLOOR):
    top = q(f"MATCH (n:{label}) RETURN max(n.{prop}) AS m")[0]["m"] or 0
    return max(top, floor - 1) + 1


def num(v, name):
    try:
        return float(v)
    except (TypeError, ValueError):
        raise ValueError(f"Enter a valid number for {name}")


# ---------- departments ----------
@app.get("/api/departments")
def departments_list():
    return jsonify(q("""
        MATCH (dep:Department)
        OPTIONAL MATCH (d:Doctor)-[:WORKS_IN]->(dep)
        RETURN dep.dept_name AS name, count(d) AS doctors,
               coalesce(dep.app_added, false) AS app_added
        ORDER BY name"""))


@app.post("/api/departments")
def department_add():
    name = (request.get_json(force=True).get("name") or "").strip()
    if not name:
        return bad("Enter a department name")
    if q("MATCH (x:Department {dept_name:$n}) RETURN x", n=name):
        return bad("That department already exists")
    q("CREATE (:Department {dept_name:$n, app_added:true})", n=name)
    return jsonify({"message": f"Department {name} added"})


@app.delete("/api/departments/<name>")
def department_delete(name):
    r = q("""MATCH (x:Department {dept_name:$n})
             WHERE x.app_added = true AND NOT EXISTS { (:Doctor)-[:WORKS_IN]->(x) }
             DETACH DELETE x RETURN count(*) AS n""", n=name)
    if not r or r[0]["n"] == 0:
        return bad("Only empty departments added through the app can be deleted", 403)
    return jsonify({"message": "Department deleted"})


# ---------- doctors ----------
@app.get("/api/doctors/full")
def doctors_full():
    return jsonify(q("""
        MATCH (d:Doctor)-[:WORKS_IN]->(dep:Department)
        OPTIONAL MATCH (d)<-[:WITH_DOCTOR]-(:Appointment)<-[:BOOKED]-(p:Patient)
        RETURN d.doctor_id AS id, d.name AS name, d.specialization AS specialization,
               dep.dept_name AS department, coalesce(d.type, '') AS type,
               count(DISTINCT p) AS patients, coalesce(d.app_added, false) AS app_added
        ORDER BY id"""))


@app.post("/api/doctors")
def doctor_add():
    d = request.get_json(force=True)
    name = (d.get("name") or "").strip()
    dept = (d.get("department") or "").strip()
    if not name or not dept:
        return bad("Enter the doctor's name and department")
    if not q("MATCH (x:Department {dept_name:$n}) RETURN x", n=dept):
        return bad("Department not found")
    new_id = next_id("Doctor", "doctor_id")
    q("""MATCH (dep:Department {dept_name:$dep})
         CREATE (:Doctor {doctor_id:$id, name:$n, specialization:$s, type:$t, app_added:true})
                -[:WORKS_IN]->(dep)""",
      dep=dept, id=new_id, n=name, s=(d.get("specialization") or "").strip(),
      t=d.get("type") or "Full-time")
    return jsonify({"message": f"Dr. {name} added to {dept}"})


@app.delete("/api/doctors/<int:did>")
def doctor_delete(did):
    r = q("""MATCH (d:Doctor {doctor_id:$id})
             WHERE d.app_added = true AND NOT EXISTS { (d)<-[:WITH_DOCTOR]-() }
             DETACH DELETE d RETURN count(*) AS n""", id=did)
    if not r or r[0]["n"] == 0:
        return bad("Only doctors added through the app, with no appointments, can be deleted", 403)
    return jsonify({"message": "Doctor deleted"})


# ---------- patients ----------
@app.get("/api/patients/full")
def patients_full():
    return jsonify(q("""
        MATCH (p:Patient)
        OPTIONAL MATCH (p)-[:BOOKED]->(a:Appointment)
        OPTIONAL MATCH (p)-[:DIAGNOSED_WITH]->(x:Disease)
        RETURN p.patient_id AS id, p.name AS name, p.gender AS gender,
               toString(p.dob) AS dob, count(DISTINCT a) AS visits,
               collect(DISTINCT x.disease_name) AS diagnoses,
               p.patient_id >= 307 AS app_added
        ORDER BY id"""))


@app.put("/api/patients/<int:pid>")
def patient_update(pid):
    d = request.get_json(force=True)
    name = (d.get("name") or "").strip()
    if not name or not d.get("dob"):
        return bad("Enter a name and a date of birth")
    r = q("""MATCH (p:Patient {patient_id:$id})
             SET p.name=$n, p.gender=$g, p.dob=date($dob) RETURN count(*) AS n""",
          id=pid, n=name, g=d.get("gender", "Male"), dob=d["dob"])
    if r[0]["n"] == 0:
        return bad("Patient not found", 404)
    return jsonify({"message": "Patient updated"})


@app.delete("/api/patients/<int:pid>/remove")
def patient_remove(pid):
    if pid < TEST_PATIENT_MIN:
        return bad("Original data cannot be deleted", 403)
    q("""MATCH (p:Patient {patient_id:$id})
         OPTIONAL MATCH (p)-[:BOOKED]->(a:Appointment)
         OPTIONAL MATCH (a)-[:HAS_TEST]->(t:LabTest) WHERE t.app_added = true
         OPTIONAL MATCH (a)-[:HAS_PRESCRIPTION]->(pr:Prescription) WHERE pr.app_added = true
         OPTIONAL MATCH (pr)-[:BILLED_AS]->(b:Bill)
         DETACH DELETE t, b, pr, a, p""", id=pid)
    return jsonify({"message": "Patient and their app-created records deleted"})


@app.post("/api/patients/<int:pid>/diagnoses")
def diagnosis_add(pid):
    d = request.get_json(force=True)
    try:
        dis = int(d.get("disease_id"))
    except (TypeError, ValueError):
        return bad("Choose a disease")
    r = q("""MATCH (p:Patient {patient_id:$p}), (x:Disease {disease_id:$d})
             MERGE (p)-[:DIAGNOSED_WITH]->(x) RETURN count(*) AS n""", p=pid, d=dis)
    if r[0]["n"] == 0:
        return bad("Patient or disease not found", 404)
    return jsonify({"message": "Diagnosis recorded"})


@app.post("/api/diseases")
def disease_add():
    d = request.get_json(force=True)
    name = (d.get("name") or "").strip()
    if not name:
        return bad("Enter a disease name")
    if q("MATCH (x:Disease {disease_name:$n}) RETURN x", n=name):
        return bad("That disease already exists")
    new_id = next_id("Disease", "disease_id")
    q("CREATE (:Disease {disease_id:$id, disease_name:$n, description:$d, app_added:true})",
      id=new_id, n=name, d=(d.get("description") or "").strip())
    return jsonify({"message": f"Disease {name} added"})


# ---------- appointments, lab tests, prescriptions ----------
@app.get("/api/appointments/full")
def appointments_full():
    return jsonify(q("""
        MATCH (p:Patient)-[:BOOKED]->(a:Appointment)-[:WITH_DOCTOR]->(d:Doctor)-[:WORKS_IN]->(dep:Department)
        OPTIONAL MATCH (a)-[:HAS_TEST]->(t:LabTest)
        OPTIONAL MATCH (a)-[:HAS_PRESCRIPTION]->(pr:Prescription)
        OPTIONAL MATCH (pr)-[:BILLED_AS]->(b:Bill)
        RETURN a.appointment_id AS id, p.name AS patient, d.name AS doctor,
               dep.dept_name AS department, count(DISTINCT t) AS tests,
               count(DISTINCT pr) AS prescriptions,
               max(b.consultation_charge + b.medicine_charge) AS bill
        ORDER BY id"""))


@app.post("/api/appointments/<int:aid>/tests")
def test_add(aid):
    d = request.get_json(force=True)
    name = (d.get("test_name") or "").strip()
    if not name:
        return bad("Enter the test name")
    try:
        cost = num(d.get("cost") or 0, "cost")
    except ValueError as e:
        return bad(str(e))
    r = q("""MATCH (a:Appointment {appointment_id:$a})
             CREATE (a)-[:HAS_TEST]->(:LabTest {test_name:$n, cost:$c, result:$r, app_added:true})
             RETURN count(*) AS n""", a=aid, n=name, c=cost, r=(d.get("result") or "Pending"))
    if r[0]["n"] == 0:
        return bad("Appointment not found", 404)
    return jsonify({"message": f"Lab test {name} added"})


@app.post("/api/appointments/<int:aid>/prescription")
def prescribe(aid):
    d = request.get_json(force=True)
    meds = d.get("medicines") or []
    if not meds:
        return bad("Choose at least one medicine")
    try:
        fee = num(d.get("consultation_charge") or 0, "consultation charge")
    except ValueError as e:
        return bad(str(e))
    if not q("MATCH (a:Appointment {appointment_id:$a}) RETURN a", a=aid):
        return bad("Appointment not found", 404)
    if q("MATCH (:Appointment {appointment_id:$a})-[:HAS_PRESCRIPTION]->() RETURN 1", a=aid):
        return bad("This appointment already has a prescription")
    pid, bid = next_id("Prescription", "prescription_id"), next_id("Bill", "bill_id")
    r = q("""MATCH (a:Appointment {appointment_id:$a})
             MATCH (m:Medicine) WHERE m.name IN $meds
             WITH a, collect(m) AS ms, sum(m.price) AS med_total
             CREATE (a)-[:HAS_PRESCRIPTION]->(pr:Prescription
                    {prescription_id:$pid, prescription_date:date(), app_added:true})
             CREATE (pr)-[:BILLED_AS]->(:Bill
                    {bill_id:$bid, consultation_charge:$fee, medicine_charge:med_total, app_added:true})
             FOREACH (m IN ms | CREATE (pr)-[:CONTAINS]->(m))
             RETURN med_total""", a=aid, meds=meds, pid=pid, bid=bid, fee=fee)
    if not r:
        return bad("None of the chosen medicines were found")
    return jsonify({"message": f"Prescription created and bill {bid} generated"})


@app.delete("/api/appointments/<int:aid>/remove")
def appointment_remove(aid):
    if aid < TEST_APPT_MIN:
        return bad("Original data cannot be deleted", 403)
    q("""MATCH (a:Appointment {appointment_id:$id})
         OPTIONAL MATCH (a)-[:HAS_TEST]->(t:LabTest) WHERE t.app_added = true
         OPTIONAL MATCH (a)-[:HAS_PRESCRIPTION]->(pr:Prescription) WHERE pr.app_added = true
         OPTIONAL MATCH (pr)-[:BILLED_AS]->(b:Bill)
         DETACH DELETE t, b, pr, a""", id=aid)
    return jsonify({"message": "Appointment and its tests, prescription and bill deleted"})


# ---------- billing ----------
@app.get("/api/bills")
def bills_list():
    return jsonify(q("""
        MATCH (p:Patient)-[:BOOKED]->(a:Appointment)-[:WITH_DOCTOR]->(d:Doctor),
              (a)-[:HAS_PRESCRIPTION]->(:Prescription)-[:BILLED_AS]->(b:Bill)
        RETURN b.bill_id AS id, p.name AS patient, d.name AS doctor,
               b.consultation_charge AS consultation, b.medicine_charge AS medicine,
               b.consultation_charge + b.medicine_charge AS total
        ORDER BY id"""))


# ---------- pharmacy ----------
@app.get("/api/medicines/full")
def medicines_full():
    return jsonify(q("""
        MATCH (m:Medicine)
        OPTIONAL MATCH (pr:Prescription)-[:CONTAINS]->(m)
        RETURN m.name AS name, m.price AS price, coalesce(m.manufacturer, '') AS manufacturer,
               count(pr) AS times, coalesce(m.app_added, false) AS app_added
        ORDER BY name"""))


@app.post("/api/medicines")
def medicine_add():
    d = request.get_json(force=True)
    name = (d.get("name") or "").strip()
    if not name:
        return bad("Enter the medicine name")
    try:
        price = num(d.get("price"), "price")
    except ValueError as e:
        return bad(str(e))
    if q("MATCH (m:Medicine {name:$n}) RETURN m", n=name):
        return bad("That medicine already exists")
    q("CREATE (:Medicine {name:$n, price:$p, manufacturer:$m, app_added:true})",
      n=name, p=price, m=(d.get("manufacturer") or "").strip())
    return jsonify({"message": f"Medicine {name} added"})


@app.delete("/api/medicines/<name>")
def medicine_delete(name):
    r = q("""MATCH (m:Medicine {name:$n})
             WHERE m.app_added = true AND NOT EXISTS { (:Prescription)-[:CONTAINS]->(m) }
             DETACH DELETE m RETURN count(*) AS n""", n=name)
    if not r or r[0]["n"] == 0:
        return bad("Only unused medicines added through the app can be deleted", 403)
    return jsonify({"message": "Medicine deleted"})
# =========================================================
# PATIENT REGISTRATION
# =========================================================

@app.post("/api/auth/register")
def patient_register():

    d = request.get_json(silent=True) or {}

    name = (d.get("name") or "").strip()
    email = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    gender = (d.get("gender") or "").strip()
    dob = (d.get("dob") or "").strip()

    if not name:
        return bad("Please enter your full name")

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return bad("Please enter a valid email address")

    if len(password) < 8:
        return bad("Password must contain at least 8 characters")

    if gender not in ("Male", "Female", "Other"):
        return bad("Please select a valid gender")

    try:
        date.fromisoformat(dob)
    except ValueError:
        return bad("Please enter a valid date of birth")

    if date.fromisoformat(dob) >= date.today():
        return bad("Date of birth must be in the past")

    # Check whether this email already has an account
    existing = q(
        """
        MATCH (a:PatientAccount {email:$email})
        RETURN a.email AS email
        """,
        email=email
    )

    if existing:
        return bad("An account with this email already exists", 409)

    password_hash = generate_password_hash(password)

    # Generate a patient ID without changing existing patient records
    result = q(
        """
        OPTIONAL MATCH (old:Patient)
        WITH coalesce(max(old.patient_id), $minimum - 1) + 1 AS new_id

        CREATE (p:Patient {
            patient_id: new_id,
            name: $name,
            gender: $gender,
            dob: date($dob)
        })

        CREATE (a:PatientAccount {
            email: $email,
            password_hash: $password_hash,
            created_at: datetime()
        })

        CREATE (p)-[:HAS_ACCOUNT]->(a)

        RETURN p.patient_id AS patient_id
        """,
        minimum=TEST_PATIENT_MIN,
        name=name,
        gender=gender,
        dob=dob,
        email=email,
        password_hash=password_hash
    )

    patient_id = result[0]["patient_id"]

    token = create_patient_token(patient_id)

    return jsonify({
        "message": "Account created successfully",
        "token": token,
        "patient": {
            "id": patient_id,
            "name": name,
            "email": email
        }
    }), 201


# =========================================================
# PATIENT LOGIN
# =========================================================

@app.post("/api/auth/login")
def patient_login():

    d = request.get_json(silent=True) or {}

    email = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""

    if not email or not password:
        return bad("Enter your email and password")

    result = q(
        """
        MATCH (p:Patient)-[:HAS_ACCOUNT]->(a:PatientAccount)
        WHERE a.email = $email

        RETURN p.patient_id AS id,
               p.name AS name,
               a.email AS email,
               a.password_hash AS password_hash
        """,
        email=email
    )

    if not result:
        return bad("Incorrect email or password", 401)

    account = result[0]

    if not check_password_hash(account["password_hash"], password):
        return bad("Incorrect email or password", 401)

    token = create_patient_token(account["id"])

    return jsonify({
        "message": "Login successful",
        "token": token,
        "patient": {
            "id": account["id"],
            "name": account["name"],
            "email": account["email"]
        }
    })


# =========================================================
# GET LOGGED-IN PATIENT
# =========================================================

@app.get("/api/auth/me")
@patient_required
def patient_me():

    result = q(
        """
        MATCH (p:Patient {patient_id:$id})
        MATCH (p)-[:HAS_ACCOUNT]->(a:PatientAccount)

        RETURN p.patient_id AS id,
               p.name AS name,
               p.gender AS gender,
               toString(p.dob) AS dob,
               a.email AS email
        """,
        id=g.patient_id
    )

    if not result:
        return bad("Patient account not found", 404)

    return jsonify({
        "patient": result[0]
    })
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)