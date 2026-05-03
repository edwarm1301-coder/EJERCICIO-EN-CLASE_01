# EJERCICIO-EN-CLASE_01
EJERCICIO EN CLASE:
Para este ejercicio desarollado en clase se tomo el siguiente prompt para el desarrollo y implementación de un software capaz de generar plantillas de configuración de Routers y Switch de la tecnologia Huawei y Cisco, realizar un bashboard de disponibilidad,remedimiento y eventos,gestionar vlan´s voice y trafico y aplicar ACL´s para controlar el trafico.

### PROMPT
Actúa como un Senior Network Software Architect & Backend Developer experto en automatización de redes. Tu tarea es diseñar y desarrollar el "Motor Lógico" en Python para un Asistente de Ingeniería de Redes Modular. 
### 1. ARQUITECTURA DEL SISTEMA El software debe ser una aplicación modular en Python. Diseña una estructura de clases donde cada módulo sea independiente pero integrable: Módulo Multi-Vendor (ConfigGen):Clase que reciba parámetros (VLAN ID, Voice Priority, IP, Mask, ACL Rules) y devuelva el set de comandos específico para Cisco (IOS) y Huawei (VRP).
Módulo de Telemetría (HealthSim):Generador de datos sintéticos que use lógica matemática para simular estados de red (Ping, SNMP, Ancho de banda). Debe incluir fluctuaciones aleatorias realistas.
Módulo de Análisis de Voz/Video (QoSAnalyzer): Motor matemático que reciba métricas de tráfico ficticio (Latencia, Jitter, Packet Loss) y calcule el MOS (Mean Opinion Score) para tráfico RTP y RTSP.
Módulo de Gestión de Reglas (PolicyManager):Lógica para validar y estructurar ACLs estándar/extendidas y asignación de etiquetas DSCP/CoS. 
### 2. ESPECIFICACIONES TÉCNICAS (CONSTRAINTS):Lenguaje: Python 3.10+ orientado a objetos. 
Simulación:No usar captura de tráfico real. Implementar funciones que simulen el comportamiento de red usando librerías como random, math o numpy.
Persistencia:Implementar una capa ligera de almacenamiento (JSON o SQLite) para guardar logs de eventos y configuraciones previas.
Interfaz:El motor debe estar preparado para ser consumido por una CLI (usando argparse o click) o una API.
### 3. ENTREGABLES REQUERIDOS 1. Estructura de Directorios:Organización profesional del proyecto (/modules, /data, /logs, main.py). 2.Código Base: Implementación del generador de comandos con lógica condicional para Cisco/Huawei. - Algoritmo de cálculo de MOS basado en la fórmula estándar de la ITU (E-model simplificado). - Simulador de dashboards que genere un JSON de rendimiento actual. 
### 3. Ejemplo de Uso: Un script de prueba que demuestre la creación de una VLAN de voz y la generación de una alerta si el Jitter simulado excede los 30ms. 
### 4. TONO Y ESTILO - Código limpio (PEP8), documentado en español, con tipado de datos (type hinting) para máxima claridad técnica.

Una vez ya obtenido el prompt se solicita la ayuda de la una inteligencia artificial, para este caso se utilizo ChatGpt y Gemini para la creacion del software y se utilizara Python 3.10+ para la ejecución del motor base.

### MOTOR DE BUSQUEDA CON PYTHON 3.10+

├── main.py

├── modules/

│   ├── config_gen.py

│   ├── health_sim.py

│   ├── qos_analyzer.py

│   └── policy_manager.py

├── data/

│   └── storage.py

├── logs/


│   └── events.log

└── requirements.txt




from __future__ import annotations

import json
import math
import os
import random
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

    def __init__(self, base_path: str = "data") -> None:
        self.base_path = base_path
        os.makedirs(self.base_path, exist_ok=True)

    def _path(self, name: str) -> str:
        return os.path.join(self.base_path, f"{name}.json")

    def save(self, name: str, payload: Dict) -> None:
        path = self._path(name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

    def load(self, name: str) -> Optional[Dict]:
        path = self._path(name)
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


class SQLiteLogger:

    def __init__(self, db_path: str = "data/events.db") -> None:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                level TEXT,
                message TEXT,
                context TEXT
            )
            """
        )
        self.conn.commit()

    def log(self, level: str, message: str, context: Optional[Dict] = None) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO events (ts, level, message, context) VALUES (?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), level, message, json.dumps(context or {})),
        )
        self.conn.commit()
        
@dataclass
class ACLRule:
    action: str  # 'permit' | 'deny'
    protocol: str  # 'ip', 'tcp', 'udp', 'icmp'
    src: str  # e.g., 'any' or '10.0.0.0 0.0.0.255'
    dst: str  # e.g., 'any' or '192.168.1.0 0.0.0.255'
    src_port: Optional[str] = None
    dst_port: Optional[str] = None


class PolicyManager:

    VALID_ACTIONS = {"permit", "deny"}
    VALID_PROTOCOLS = {"ip", "tcp", "udp", "icmp"}
    VALID_DSCP = {
        "ef": 46,
        "af41": 34,
        "af31": 26,
        "cs3": 24,
        "cs0": 0,
    }

    def validate_acl(self, rules: List[ACLRule]) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        for i, r in enumerate(rules, start=1):
            if r.action not in self.VALID_ACTIONS:
                errors.append(f"Regla {i}: acción inválida {r.action}")
            if r.protocol not in self.VALID_PROTOCOLS:
                errors.append(f"Regla {i}: protocolo inválido {r.protocol}")
            if r.protocol in {"tcp", "udp"} and not (r.src_port or r.dst_port):
                errors.append(
                    f"Regla {i}: tcp/udp requiere src_port o dst_port"
                )
        return (len(errors) == 0, errors)

    def dscp_value(self, label: str) -> int:
        if label.lower() not in self.VALID_DSCP:
            raise ValueError(f"DSCP desconocido: {label}")
        return self.VALID_DSCP[label.lower()]

    def build_cisco_acl(self, name: str, rules: List[ACLRule]) -> List[str]:
        ok, errors = self.validate_acl(rules)
        if not ok:
            raise ValueError("; ".join(errors))
        cmds = [f"ip access-list extended {name}"]
        for r in rules:
            line = f" {r.action} {r.protocol} {r.src} {r.dst}"
            if r.src_port:
                line += f" eq {r.src_port}"
            if r.dst_port:
                line += f" eq {r.dst_port}"
            cmds.append(line)
        cmds.append(" exit")
        return cmds

    def build_huawei_acl(self, acl_id: int, rules: List[ACLRule]) -> List[str]:
        ok, errors = self.validate_acl(rules)
        if not ok:
            raise ValueError("; ".join(errors))
        cmds = [f"acl number {acl_id}"]
        seq = 5
        for r in rules:
            line = f" rule {seq} {r.action} {r.protocol} source {r.src} destination {r.dst}"
            if r.src_port:
                line += f" source-port eq {r.src_port}"
            if r.dst_port:
                line += f" destination-port eq {r.dst_port}"
            cmds.append(line)
            seq += 5
        cmds.append(" quit")
        return cmds


@dataclass
class VLANParams:
    vlan_id: int
    name: str
    ip: str
    mask: str
    voice: bool = False
    voice_vlan_id: Optional[int] = None
    qos_dscp: Optional[str] = None


class ConfigGen:

    def __init__(self, policy: PolicyManager) -> None:
        self.policy = policy

    def cisco_vlan(self, p: VLANParams) -> List[str]:
        cmds = [
            f"vlan {p.vlan_id}",
            f" name {p.name}",
            " exit",
            f"interface vlan {p.vlan_id}",
            f" ip address {p.ip} {p.mask}",
        ]
        if p.qos_dscp:
            dscp = self.policy.dscp_value(p.qos_dscp)
            cmds.append(f" qos trust dscp")
            cmds.append(f" mls qos map cos-dscp 0 8 16 24 32 46 48 56")
            cmds.append(f" ! DSCP objetivo {dscp}")
        if p.voice and p.voice_vlan_id:
            cmds.extend([
                " exit",
                "interface range GigabitEthernet1/0/1-24",
                f" switchport access vlan {p.vlan_id}",
                f" switchport voice vlan {p.voice_vlan_id}",
                " spanning-tree portfast",
                " exit",
            ])
        cmds.append(" no shutdown")
        return cmds

    def huawei_vlan(self, p: VLANParams) -> List[str]:
        cmds = [
            f"vlan {p.vlan_id}",
            f" description {p.name}",
            " quit",
            f"interface Vlanif {p.vlan_id}",
            f" ip address {p.ip} {p.mask}",
        ]
        if p.qos_dscp:
            dscp = self.policy.dscp_value(p.qos_dscp)
            cmds.append(f" trust dscp")
            cmds.append(f" remark dscp {dscp}")
        if p.voice and p.voice_vlan_id:
            cmds.extend([
                " quit",
                "interface GigabitEthernet0/0/1 to GigabitEthernet0/0/24",
                f" port default vlan {p.vlan_id}",
                f" voice-vlan {p.voice_vlan_id} enable",
                " stp edged-port enable",
                " quit",
            ])
        cmds.append(" undo shutdown")
        return cmds

class HealthSim:


    def __init__(self, seed: Optional[int] = None) -> None:
        self.rng = random.Random(seed)

    def _bounded_noise(self, base: float, jitter: float, min_v: float, max_v: float) -> float:
        val = base + self.rng.uniform(-jitter, jitter)
        return max(min_v, min(max_v, val))

    def ping_ms(self) -> float:
        return self._bounded_noise(base=20.0, jitter=10.0, min_v=1.0, max_v=200.0)

    def jitter_ms(self) -> float:
        return self._bounded_noise(base=10.0, jitter=25.0, min_v=0.0, max_v=150.0)

    def packet_loss_pct(self) -> float:
        # Distribución sesgada (la mayoría cercano a 0)
        val = abs(self.rng.gauss(0.5, 0.7))
        return min(10.0, val)

    def bandwidth_mbps(self) -> float:
        # Simula uso con oscilación sinusoidal + ruido
        t = self.rng.random() * 2 * math.pi
        base = 100.0 + 40.0 * math.sin(t)
        noise = self.rng.uniform(-10.0, 10.0)
        return max(1.0, base + noise)

    def dashboard(self) -> Dict:
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "ping_ms": round(self.ping_ms(), 2),
            "jitter_ms": round(self.jitter_ms(), 2),
            "packet_loss_pct": round(self.packet_loss_pct(), 3),
            "bandwidth_mbps": round(self.bandwidth_mbps(), 2),
        }
        return data

@dataclass
class QoSMetrics:
    latency_ms: float
    jitter_ms: float
    packet_loss_pct: float


class QoSAnalyzer:

    def _effective_latency(self, m: QoSMetrics) -> float:
        # Aproximación: latencia efectiva incluye jitter
        return m.latency_ms + 2 * m.jitter_ms

    def _r_factor(self, m: QoSMetrics) -> float:
        # E-model simplificado
        d = self._effective_latency(m)
        if d < 160:
            Id = 0.024 * d
        else:
            Id = 0.024 * d + 0.11 * (d - 160)

        # Pérdida de paquetes impacta Ie
        Ie = 30 * math.log10(1 + m.packet_loss_pct)

        R = 94.2 - Id - Ie
        return max(0.0, min(100.0, R))

    def mos(self, m: QoSMetrics) -> float:
        R = self._r_factor(m)
        mos = 1 + 0.035 * R + R * (R - 60) * (100 - R) * 7e-6
        return round(max(1.0, min(4.5, mos)), 3)

    def classify(self, mos: float) -> str:
        if mos >= 4.3:
            return "Excelente"
        if mos >= 4.0:
            return "Bueno"
        if mos >= 3.6:
            return "Aceptable"
        if mos >= 3.1:
            return "Pobre"
        return "Malo"

def example_run() -> None:
    storage = JSONStorage()
    logger = SQLiteLogger()

    policy = PolicyManager()
    cfg = ConfigGen(policy)
    sim = HealthSim(seed=42)
    qos = QoSAnalyzer()

    # 1) Crear VLAN de voz
    params = VLANParams(
        vlan_id=10,
        name="DATA",
        ip="10.10.10.1",
        mask="255.255.255.0",
        voice=True,
        voice_vlan_id=20,
        qos_dscp="ef",
    )

    cisco_cmds = cfg.cisco_vlan(params)
    huawei_cmds = cfg.huawei_vlan(params)

    storage.save("last_config_cisco", {"cmds": cisco_cmds})
    storage.save("last_config_huawei", {"cmds": huawei_cmds})

    logger.log("INFO", "VLAN de voz generada", asdict(params))

    # 2) Simulación y alerta por jitter > 30 ms
    dashboard = sim.dashboard()
    storage.save("last_dashboard", dashboard)

    metrics = QoSMetrics(
        latency_ms=dashboard["ping_ms"],
        jitter_ms=dashboard["jitter_ms"],
        packet_loss_pct=dashboard["packet_loss_pct"],
    )

    mos = qos.mos(metrics)
    quality = qos.classify(mos)

    print("=== CONFIG CISCO ===")
    print("\n".join(cisco_cmds))
    print("\n=== CONFIG HUAWEI ===")
    print("\n".join(huawei_cmds))

    print("\n=== DASHBOARD ===")
    print(json.dumps(dashboard, indent=2))

    print(f"\nMOS: {mos} ({quality})")

    if dashboard["jitter_ms"] > 30.0:
        msg = f"ALERTA: Jitter alto {dashboard['jitter_ms']} ms"
        print(msg)
        logger.log("WARN", msg, dashboard)


if __name__ == "__main__":
    example_run()

### Una vez ya obtenido la base del motor de busqueda ejecutamos en el bash el siguiente comando:
python main.py

## 
Obtendrás:
Configuración Cisco y Huawei

Dashboard simulado (JSON)

MOS calculado

Alerta automática si jitter > 30 ms

Y para simplicar un poco el ejercicio se segmentara cada item de la siguiente forma:

## 🧱 Estructura del Proyecto

```
network-assistant/
│
├── backend/
│   ├── main.py
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── config_gen.py
│   │   ├── health_sim.py
│   │   ├── qos_analyzer.py
│   │   └── policy_manager.py
│   ├── data/
│   │   └── storage.py
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── index.html
│   └── package.json
│
├── README.md
└── .gitignore
```

---

# 🔧 BACKEND

## backend/requirements.txt

```
fastapi
uvicorn
```

---

## backend/main.py

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from modules.health_sim import HealthSim
from modules.qos_analyzer import QoSAnalyzer, QoSMetrics
from modules.config_gen import ConfigGen, VLANParams
from modules.policy_manager import PolicyManager

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

sim = HealthSim()
qos = QoSAnalyzer()
policy = PolicyManager()
cfg = ConfigGen(policy)

@app.get("/dashboard")
def dashboard():
    data = sim.dashboard()

    metrics = QoSMetrics(
        latency_ms=data["ping_ms"],
        jitter_ms=data["jitter_ms"],
        packet_loss_pct=data["packet_loss_pct"],
    )

    mos = qos.mos(metrics)

    return {
        "metrics": data,
        "mos": mos,
        "quality": qos.classify(mos),
        "alerts": ["High jitter"] if data["jitter_ms"] > 30 else []
    }

@app.get("/config")
def config():
    params = VLANParams(
        vlan_id=10,
        name="DATA",
        ip="10.10.10.1",
        mask="255.255.255.0",
        voice=True,
        voice_vlan_id=20,
        qos_dscp="ef",
    )

    return {
        "cisco": cfg.cisco_vlan(params),
        "huawei": cfg.huawei_vlan(params)
    }
```

---

## modules/config_gen.py

```python
from dataclasses import dataclass

@dataclass
class VLANParams:
    vlan_id: int
    name: str
    ip: str
    mask: str
    voice: bool = False
    voice_vlan_id: int | None = None
    qos_dscp: str | None = None

class ConfigGen:
    def __init__(self, policy):
        self.policy = policy

    def cisco_vlan(self, p: VLANParams):
        return [f"vlan {p.vlan_id}", f"name {p.name}"]

    def huawei_vlan(self, p: VLANParams):
        return [f"vlan {p.vlan_id}", f"description {p.name}"]
```

---

## modules/health_sim.py

```python
import random
import math
from datetime import datetime

class HealthSim:
    def dashboard(self):
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "ping_ms": round(random.uniform(5, 100), 2),
            "jitter_ms": round(random.uniform(0, 80), 2),
            "packet_loss_pct": round(random.uniform(0, 5), 2),
            "bandwidth_mbps": round(100 + 50 * math.sin(random.random()), 2)
        }
```

---

## modules/qos_analyzer.py

```python
from dataclasses import dataclass
import math

@dataclass
class QoSMetrics:
    latency_ms: float
    jitter_ms: float
    packet_loss_pct: float

class QoSAnalyzer:
    def mos(self, m: QoSMetrics):
        R = 94.2 - (0.024 * m.latency_ms) - (30 * math.log10(1 + m.packet_loss_pct))
        return round(1 + 0.035 * R, 2)

    def classify(self, mos: float):
        return "Good" if mos > 4 else "Bad"
```

---

## modules/policy_manager.py

```python
class PolicyManager:
    def dscp_value(self, label):
        return {"ef": 46}.get(label, 0)
```

---

# 🎨 FRONTEND

## frontend/src/App.jsx

```jsx
import { useEffect, useState } from "react";

export default function App() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/dashboard")
      .then(r => r.json())
      .then(setData);
  }, []);

  if (!data) return <div>Loading...</div>;

  return (
    <div>
      <h1>Dashboard</h1>
      <p>Ping: {data.metrics.ping_ms}</p>
      <p>Jitter: {data.metrics.jitter_ms}</p>
      <p>MOS: {data.mos}</p>
    </div>
  );
}
```

---

# 📄 README.md

```
# Network Assistant

## Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload

## Frontend
cd frontend
npm install
npm run dev
```


