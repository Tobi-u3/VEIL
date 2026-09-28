# Third-party sources and acknowledgements

- Zeek documentation: https://docs.zeek.org/en/current/ — packet/DNS event APIs and logging framework.
- FoxIO JA4 plugin: https://github.com/FoxIO-LLC/ja4/tree/main/zeek — installed separately; no plugin code redistributed. Review upstream licences for JA4 versus the wider JA4+ suite.
- KitNET: https://github.com/ymirsky/KitNET-py — commit 02eb5e804568ee9f3968d4fc5bdfd37a9c0bc190. The five implementation Python files and MIT licence are bundled. Compatibility edits: numpy.Inf -> numpy.inf in dA.py; clip the sigmoid exponent to [-700,700] in utils.py to avoid overflow. The upstream example datasets and paper are not included.
- NumPy, Pandas, scikit-learn, River, SHAP, NetworkX, FastAPI, Uvicorn, psycopg, Scapy: installed through requirements.txt with upstream licences.
- React, React Flow (@xyflow/react), Tailwind, Vite, TypeScript, Lucide: dependencies declared in frontend/package.json and package-lock.json. Their notices remain in installed packages/build output as supplied.

The supplied Claude files were inspected as a starting reference; this package replaces the batch-only feature pipeline and supplies a separate bounded streaming application and namespace lab. Your original uploads are unchanged.
