from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Table, Column, Integer, String, Float, MetaData, select
from sqlalchemy.orm import sessionmaker
import pandas as pd
import joblib

# ------------------- إعداد قاعدة البيانات -------------------
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
Session = sessionmaker(bind=engine)
session = Session()

# ------------------- تحميل الموديل -------------------
model = joblib.load("AI_model.pkl")

# ------------------- إعداد FastAPI -------------------
app = FastAPI()

# ------------------- نموذج البيانات -------------------
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

# ------------------- دالة للتشفير (Encoding) -------------------
def prepare_features(data):
    df = pd.DataFrame([data])
    
    # التأكد من القيم النصية
    df['protocol'] = df['protocol'].astype(str)
    df['tcp_flags'] = df['tcp_flags'].astype(str)
    
    # عمل one-hot encoding
    df = pd.get_dummies(df, columns=['protocol', 'tcp_flags'])
    
    # إضافة أي عمود ناقص وضبط الترتيب حسب الموديل
    for col in model.feature_names_in_:
        if col not in df.columns:
            df[col] = 0

    df = df[model.feature_names_in_]
    
    # تحويل كل شيء float لتجنب dtype issues
    df = df.astype(float)
    return df


# ------------------- POST: تقييم وتخزين traffic -------------------
@app.post("/predict")
def predict_traffic(traffic: Traffic):
    data = traffic.dict()
    features = prepare_features(data)
    pred_label = model.predict(features)[0]
    data["predicted_label"] = pred_label

    # تخزين في DB
    ins = traffic_table.insert().values(**data)
    with engine.begin() as conn:
        conn.execute(ins)

    return {"predicted_label": pred_label, "data": data}


# ------------------- GET: آخر 10 traffic -------------------
@app.get("/", response_class=HTMLResponse)
def last_10_traffic_page():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>Last 10 Traffic Records</title>
    <style>
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
      th { background-color: #f2f2f2; }
    </style>
    </head>
    <body>
    <h2>Last 10 Traffic Records</h2>
    <table id="trafficTable">
      <thead>
        <tr>
          <th>ID</th>
          <th>Dest IP</th>
          <th>Source MAC</th>
          <th>Dest MAC</th>
          <th>Packet Count</th>
          <th>Packet/sec</th>
          <th>Byte Count</th>
          <th>Byte/sec</th>
          <th>TCP Flags</th>
          <th>Connection Attempts</th>
          <th>Unique Ports</th>
          <th>Protocol</th>
          <th>Predicted Label</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>

    <script>
    async function fetchTraffic() {
        const response = await fetch('/api/last10');
        const data = await response.json();
        console.log(data); // تحقق من البيانات
        const tbody = document.querySelector('#trafficTable tbody');
        tbody.innerHTML = '';
        data.forEach(row => {
            const tr = document.createElement('tr');
            Object.values(row).forEach(val => {
                const td = document.createElement('td');
                td.textContent = val;
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });
    }
    fetchTraffic();
    setInterval(fetchTraffic, 5000);
    </script>
    </body>
    </html>
    """
    return html_content

@app.get("/alltraffic_page", response_class=HTMLResponse)
def all_traffic_page():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>All Traffic Records</title>
    <style>
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
      th { background-color: #f2f2f2; }
    </style>
    </head>
    <body>
    <h2>All Traffic Records</h2>
    <table id="trafficTable">
      <thead>
        <tr>
          <th>ID</th>
          <th>Dest IP</th>
          <th>Source MAC</th>
          <th>Dest MAC</th>
          <th>Packet Count</th>
          <th>Packet/sec</th>
          <th>Byte Count</th>
          <th>Byte/sec</th>
          <th>TCP Flags</th>
          <th>Connection Attempts</th>
          <th>Unique Ports</th>
          <th>Protocol</th>
          <th>Predicted Label</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>

    <script>
    async function fetchTraffic() {
        const response = await fetch('/api/alltraffic');
        const data = await response.json();
        console.log(data); // تحقق من البيانات
        const tbody = document.querySelector('#trafficTable tbody');
        tbody.innerHTML = '';
        data.forEach(row => {
            const tr = document.createElement('tr');
            Object.values(row).forEach(val => {
                const td = document.createElement('td');
                td.textContent = val;
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });
    }
    fetchTraffic();
    setInterval(fetchTraffic, 5000);
    </script>
    </body>
    </html>
    """
    return html_content

# ------------------- API JSON: آخر 10 -------------------
@app.get("/api/last10")
def api_last_10_traffic():
    conn = engine.connect()
    sel = select(traffic_table).order_by(traffic_table.c.id_num.desc()).limit(10)
    result = conn.execute(sel).mappings().all()  # <<<<<<<<<< استخدم .mappings()
    conn.close()
    return [dict(row) for row in result]

# ------------------- API JSON: كل traffic -------------------
@app.get("/api/alltraffic")
def api_all_traffic():
    conn = engine.connect()
    sel = select(traffic_table).order_by(traffic_table.c.id_num.desc())
    result = conn.execute(sel).mappings().all()  # <<<<<<<<<< استخدم .mappings()
    conn.close()
    return [dict(row) for row in result]
