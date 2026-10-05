# Dependencies

Python dependencies are listed in requirements.txt: NumPy, Pandas, scikit-learn, SHAP, NetworkX, FastAPI, Uvicorn, psycopg, Scapy, HTTPX and joblib. Frontend dependencies and lockfile are in frontend/package.json and package-lock.json. Their upstream licences apply.

Zeek and tcpreplay are externally installed capture/replay tools. Optional JA4 comes from the FoxIO Zeek plugin; it is not bundled. The previous KitNET implementation and artifacts are not used or included in this version.

IsolationForest score definition: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
