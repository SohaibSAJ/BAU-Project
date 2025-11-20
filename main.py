from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
import pandas as pd
import joblib
from sqlalchemy import create_engine, Table, Column, Integer, String, Float, MetaData, select

# ---------------- Database Setup ----------------
DATABASE_URL = "postgresql://postgres:987456@localhost:5432/Traffic_Analyzer"
engine = create_engine(DATABASE_URL)
metadata = MetaData()

traffic_table = Table(
    "traffic_data", metadata,
    Column("id_num", Integer, primary_key=True, autoincrement=True),
    Column("dest_ip", String),
    Column("source_mac", String),
    Column("dest_mac", String),
    Column("packet_count", Integer),
    Column("packet_per_sec", Float),
    Column("byte_count", Integer),
    Column("byte_per_sec", Float),
    Column("tcp_flags", String),
    Column("connection_attempts", Integer),
    Column("unique_ports", Integer),
    Column("protocol", String),
    Column("predicted_label", String)
)

metadata.create_all(engine)

# ---------------- Load AI Model ----------------
model = joblib.load("AI_model.pkl")

# ---------------- FastAPI ----------------
app = FastAPI()

# ---------------- Pydantic Model ----------------
class Traffic(BaseModel):
    dest_ip: str
    source_mac: str
    dest_mac: str
    packet_count: int
    packet_per_sec: float
    byte_count: int
    byte_per_sec: float
    tcp_flags: str
    connection_attempts: int
    unique_ports: int
    protocol: str

# ---------------- Encode Features ----------------
def prepare_features(data):
    df = pd.DataFrame([data])
    df['protocol'] = df['protocol'].astype(str)
    df['tcp_flags'] = df['tcp_flags'].astype(str)
    df = pd.get_dummies(df, columns=['protocol','tcp_flags'])
    for col in model.feature_names_in_:
        if col not in df.columns:
            df[col] = 0
    df = df[model.feature_names_in_]
    return df.astype(float)

# ---------------- API: Predict ----------------
@app.post("/predict")
def predict_traffic(traffic: Traffic):
    data = traffic.dict()
    features = prepare_features(data)
    pred_label = model.predict(features)[0]
    data["predicted_label"] = pred_label
    ins = traffic_table.insert().values(**data)
    with engine.begin() as conn:
        conn.execute(ins)
    return {"predicted_label": pred_label, "data": data}

# ---------------- Serve Dashboard ----------------
@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return FileResponse("dashboard.html")

# ---------------- API: Get All Traffic ----------------
@app.get("/api/alltraffic")
def api_all_traffic():
    with engine.connect() as conn:
        sel = select(traffic_table).order_by(traffic_table.c.id_num.desc())
        result = conn.execute(sel).mappings().all()
    return [dict(row) for row in result]
