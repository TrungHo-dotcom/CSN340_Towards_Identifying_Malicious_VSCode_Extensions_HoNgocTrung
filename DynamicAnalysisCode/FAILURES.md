# Misclassification & Root-Cause Report

Generated: 2026-06-21T17:32:16.101Z
Source CSV: res/all.csv

## Confusion matrix (strict: positive = MALICIOUS)

|              | Predicted MAL | Predicted BENIGN |
|--------------|---------------|------------------|
| **Actual MAL**    | TP = 48 | FN = 72 |
| **Actual BENIGN** | FP = 5 | TN = 44 |

Precision **90.6%**  ·  Recall **40.0%**  ·  F1 **55.5%**  ·  Accuracy **54.4%**

---

## FALSE NEGATIVES (missed malware) — 72

_Malicious samples our pipeline did NOT flag as MALICIOUS._

### ❌ 498-00.httpformat (v1.1.2)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ AutoMind.automindX (v1.0.1)  — predicted SUSPICIOUS
**Root cause:** Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.
*(events=26, net=13, exec=0, static IOCs=1)*

### ❌ BenjaminFriedl.lexica-img-fix (v0.0.1)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ BlockchainIndustries.bitcoin-toolkit (v0.0.1)  — predicted SUSPICIOUS
**Root cause:** Code never executed its payload in the sandbox (gated/dormant) but static did see indicators that scored below threshold — consider lowering the static threshold or strengthening de-obfuscation.
*(events=0, net=0, exec=0, static IOCs=1)*

### ❌ BlockchainIndustries.hardhat-toolkit (v0.0.1)  — predicted SUSPICIOUS
**Root cause:** Code never executed its payload in the sandbox (gated/dormant) but static did see indicators that scored below threshold — consider lowering the static threshold or strengthening de-obfuscation.
*(events=0, net=0, exec=0, static IOCs=1)*

### ❌ BlockchainIndustries.solana-toolkit (v0.0.1)  — predicted SUSPICIOUS
**Root cause:** Code never executed its payload in the sandbox (gated/dormant) but static did see indicators that scored below threshold — consider lowering the static threshold or strengthening de-obfuscation.
*(events=0, net=0, exec=0, static IOCs=1)*

### ❌ Bobronium.darcula-from-pycharm (v0.9.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ CodamaSoftware.ai-docs-and-comments (v0.0.8)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ EchelonStudios.blockchain-language-support (v1.0.1)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ EthCompiler.among-eth (v1.0.2)  — predicted SUSPICIOUS
**Root cause:** Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.
*(events=4, net=1, exec=0, static IOCs=0)*

### ❌ JohnGaffney.blankebesxstnion (v1.0.2)  — predicted SUSPICIOUS
**Root cause:** Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.
*(events=4, net=1, exec=0, static IOCs=0)*

### ❌ OPENEDAI.OPENEDAI (v0.4.51)  — predicted BENIGN
**Root cause:** Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.
*(events=1, net=0, exec=0, static IOCs=0)*

### ❌ OktayAydoan.smarty-formatter (v2.1.2)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ priyanshumallick.clipboard-history-manager (v0.1.0)  — predicted BENIGN
**Root cause:** Dynamic analysis was killed/timed-out before any behaviour surfaced, and static found no IOC. Mitigation: raise per-sample timeout or memory guard.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ Puglight.discoverito (v0.0.1)  — predicted SUSPICIOUS
**Root cause:** Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.
*(events=9, net=0, exec=4, static IOCs=0)*

### ❌ Puglight.inspiredaily (v0.0.1)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ Puglight.persistorito (v0.0.1)  — predicted SUSPICIOUS
**Root cause:** Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.
*(events=4, net=0, exec=1, static IOCs=0)*

### ❌ RabobankAI.rabobank-code-assistant (v0.5.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.

### ❌ SFRA-FAKA.sfra-toolkit (v0.0.2)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ SmartContractAI.solaibot (v1.4.2)  — predicted SUSPICIOUS
**Root cause:** Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.
*(events=4, net=1, exec=0, static IOCs=0)*

### ❌ StefanYosif.axion-ai (v1.0.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ Vsceue.volar-vscode (v3.1.6)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ WhenSunset.chatgpt-china (v9.5.3)  — predicted BENIGN
**Root cause:** Runtime activity occurred but matched no malicious signature (behaviour indistinguishable from benign at observation time).
*(events=1, net=0, exec=0, static IOCs=0)*

### ❌ ab-498.cppformat (v1.0.8)  — predicted BENIGN
**Root cause:** Runtime activity occurred but matched no malicious signature (behaviour indistinguishable from benign at observation time).
*(events=1, net=0, exec=0, static IOCs=0)*

### ❌ ab-498.cppplayground (v1.0.42)  — predicted SUSPICIOUS
**Root cause:** Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.
*(events=38, net=17, exec=0, static IOCs=1)*

### ❌ ab-498.httpformat (v1.1.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ ab-498.pythonformat (v1.0.50)  — predicted BENIGN
**Root cause:** Runtime activity occurred but matched no malicious signature (behaviour indistinguishable from benign at observation time).
*(events=2, net=0, exec=0, static IOCs=0)*

### ❌ bphpburnsus.Iconesvscode (v12.15.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ codevsce.codelddb-vscode (v1.11.9)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ csvmech.csvrainbow (v3.3.1)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ cweijamysq.sync-settings-vscode (v0.18.2)  — predicted BENIGN
**Root cause:** Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.
*(events=7, net=0, exec=0, static IOCs=0)*

### ❌ eamodas.shiny-vscode (v1.3.2)  — predicted BENIGN
**Root cause:** Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.
*(events=2, net=0, exec=0, static IOCs=0)*

### ❌ embeddteam.embedded-build-analyzer (v1.1.3)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ embeddteam.embedded-cortex-debug (v1.14.0)  — predicted SUSPICIOUS
**Root cause:** Code never executed its payload in the sandbox (gated/dormant) but static did see indicators that scored below threshold — consider lowering the static threshold or strengthening de-obfuscation.
*(events=0, net=0, exec=0, static IOCs=1)*

### ❌ embeddteam.embedded-cortex-debug (v1.14.1)  — predicted SUSPICIOUS
**Root cause:** Code never executed its payload in the sandbox (gated/dormant) but static did see indicators that scored below threshold — consider lowering the static threshold or strengthening de-obfuscation.
*(events=0, net=0, exec=0, static IOCs=1)*

### ❌ embeddteam.embeddedprojectmanager (v0.0.1)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ embeddteam.embeddedprojectmanager (v0.0.2)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ flutcode.flutter-extension (v3.122.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ garytyler.darcula-pycharm (v1.0.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ hajoo.poisoned-extension (v1.0.3)  — predicted SUSPICIOUS
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.

### ❌ krabt.krabt-extension-pack (v1.0.1)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ krabt.krabt-proto (v0.5.7)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ kraftwer1.darcula-extra (v0.6.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ labfile.labfile (v0.0.5)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ ovixcodes.basedpyright-vscode (v1.34.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ rafaelrenanpacheco.darcula-theme (v1.18.1)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.glm-copilot (v1.0.1)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.glm-copilot (v1.0.12)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.glm-copilot (v1.0.4)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.glm-copilot (v1.0.7)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.glm-copilot (v1.1.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.kimi-coding-copilot (v1.0.12)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.kimi-coding-copilot (v1.1.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.kimi-copilot (v1.0.1)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.kimi-copilot (v1.0.12)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.kimi-copilot (v1.0.4)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.kimi-copilot (v1.0.7)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.kimi-copilot (v1.1.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.mimo-copilot (v1.0.1)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.mimo-copilot (v1.0.12)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.mimo-copilot (v1.0.4)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.mimo-copilot (v1.0.7)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.mimo-copilot (v1.1.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.minimax-copilot (v1.0.1)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.minimax-copilot (v1.0.12)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.minimax-copilot (v1.0.4)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.minimax-copilot (v1.0.7)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ sanchuan.minimax-copilot (v1.1.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ serialt.sugar-proto (v0.5.7)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ siffat-ahmed.ai-autocomplete-siffat-ahmed (v0.1.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ wlnxingdev.free-senltig (v17.6.0)  — predicted BENIGN
**Root cause:** No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.
*(events=0, net=0, exec=0, static IOCs=0)*

### ❌ zhukunpeng.chat-moss (v8.0.0)  — predicted BENIGN
**Root cause:** Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.
*(events=3, net=0, exec=0, static IOCs=0)*

---

## FALSE POSITIVES (benign flagged as malware) — 5

_Benign samples our pipeline wrongly flagged as MALICIOUS._

### ⚠️ Gruntfuggly.todo-tree (v0.0.226)  — predicted MALICIOUS
**Root cause:** Download-cradle proximity matched benign library text (LOLBIN keyword near an unrelated URL). Fix: tighten proximity / restrict to app code.

### ⚠️ PKief.material-icon-theme (v5.35.0)  — predicted MALICIOUS
**Root cause:** Download-cradle proximity matched benign library text (LOLBIN keyword near an unrelated URL). Fix: tighten proximity / restrict to app code.

### ⚠️ TabNine.tabnine-vscode (v3.335.0)  — predicted MALICIOUS
**Root cause:** Generic process/socket marker fired on a legitimate language-server / dev-tool that uses child_process. Fix: scan generic markers in the extension's own code only, not node_modules.

### ⚠️ formulahendry.code-runner (v0.12.2)  — predicted MALICIOUS
**Root cause:** Download-cradle proximity matched benign library text (LOLBIN keyword near an unrelated URL). Fix: tighten proximity / restrict to app code.

### ⚠️ streetsidesoftware.code-spell-checker (v4.6.0)  — predicted MALICIOUS
**Root cause:** Download-cradle proximity matched benign library text (LOLBIN keyword near an unrelated URL). Fix: tighten proximity / restrict to app code.
