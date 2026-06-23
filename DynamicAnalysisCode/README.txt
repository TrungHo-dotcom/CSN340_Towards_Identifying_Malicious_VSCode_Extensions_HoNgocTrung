DYNAMIC SANDBOX — full toolset (CSN 304)            sandbox v2.1
================================================================
Keep ALL these files in the SAME folder:
  sandbox.js, mock-vscode.js, data-intel.js,
  run_dataset.js, run_batch.js, aggregate.js, evaluate.js, package.json

The crash "Cannot find module './mock-vscode'" happens when sandbox.js is copied
to a new folder WITHOUT its siblings. sandbox.js prints a clear setup error if
any required sibling is missing.

----------------------------------------------------------------
WHAT'S NEW IN v2.1 (detection fixes)
----------------------------------------------------------------
1. Auto-resolves the target. You can now point the sandbox at:
     • a .vsix file              (it unzips automatically)
     • the extension/ folder
     • the <publisher.name>/<version> parent folder
   It descends to wherever package.json actually lives, so the old
   "[FATAL] package.json not found" no longer happens.

2. OS-gate defeat. Many payloads do `if (process.platform!=='win32') return;`
   or `if (os.platform()!=='win32') return;` and stay silent on the Linux VM.
   The sandbox now SPOOFS the platform (default win32) so those branches run.
   Override per run:  SANDBOX_OS=darwin SANDBOX_ARCH=arm64 node sandbox.js <x>

3. Outbound-message logging (supervisor requirement). Every transmission the
   extension makes (http/https body, fetch body, raw TCP, axios payload) is
   captured in report.outbound_messages with destination, headers, the full
   body, and a decoded view of any base64/url/hex content. Live lines: 📤 MSG-OUT

4. Behavioural verdict. Each report now ends with an explainable verdict:
   MALICIOUS / SUSPICIOUS / BENIGN, a score, and the reasons — ready for the
   confusion matrix in the report.

----------------------------------------------------------------
RUN ONE EXTENSION
----------------------------------------------------------------
  node sandbox.js <path-to-extension | .vsix file | version folder>
  # faster wait for quick checks:
  SANDBOX_WAIT_MS=8000 node sandbox.js ./0xS1rx58D3V.ChatGPT-B0T/0.0.1.vsix

----------------------------------------------------------------
RUN A WHOLE DATASET  (this is what you use for the 100 + 100 samples)
----------------------------------------------------------------
  # 1) the malicious set (ground truth = 1):
  node run_dataset.js --input /path/to/malicious --output ./results --label 1 \
       --wait 10000 --csv ./results/all.csv

  # 2) the benign set (ground truth = 0), appended into the SAME csv:
  node run_dataset.js --input /path/to/benign --output ./results --label 0 \
       --wait 10000 --csv ./results/all.csv --append

  # 3) confusion matrix + precision / recall / F1:
  node evaluate.js ./results/all.csv

  # 4) FORENSIC BEHAVIOUR REPORT (what each sample did + why malicious + MITRE):
  node explain.js ./results
  #    → writes analysis.md next to every sample, and ./results/ANALYSIS.md (combined)

run_dataset.js searches recursively, so it handles the <publisher.name>/<ver>.vsix
layout directly. Each sample's full report is kept under ./results/<sample>/extension/.

  node aggregate.js ./results --label 1   # category + destination roll-up

----------------------------------------------------------------
FULL PIPELINE (the order to run things)
----------------------------------------------------------------
  preprocess.js  → static IOC scan of every file incl node_modules   (per sample)
  sandbox.js     → dynamic detonation in the instrumented VM         (per sample)
                   + intel breakdown: purpose/actions/data/network
  run_dataset.js → runs BOTH over a whole folder, FINAL = max(both)  (batch + CSV)
  evaluate.js    → confusion matrix / precision / recall / F1        (from CSV)
  explain.js     → human-readable forensic report per sample         (the "why")
  failures.js    → FP/FN collector + automated ROOT-CAUSE (Limitations material)
  recombine.js   → merge fresh static with saved dynamic (no 1.5h re-run)
  download_benign.py → fetch the benign control set from the Marketplace

  Definitive run (both classes → one CSV → metrics → forensics → failures):
    node run_dataset.js --input <MAL>    --output ./res --label 1 --csv ./res/all.csv
    node run_dataset.js --input <BENIGN> --output ./res --label 0 --csv ./res/all.csv --append
    node explain.js  ./res
    node evaluate.js ./res/all.csv
    node failures.js ./res/all.csv ./res
