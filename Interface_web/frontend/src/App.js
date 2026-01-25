import React, { useState } from "react";

const containerStyle = {
  maxWidth: "1200px",
  margin: "0 auto",
  padding: "2rem 1.5rem",
  fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
  backgroundColor: "#050816",
  minHeight: "100vh",
  color: "#e5e7eb",
};

const cardStyle = {
  backgroundColor: "#0b1120",
  borderRadius: "1rem",
  padding: "1.5rem",
  boxShadow: "0 18px 45px rgba(0,0,0,0.6)",
  border: "1px solid rgba(148,163,184,0.25)",
  marginBottom: "1.5rem",
};

const sectionTitleStyle = {
  fontSize: "1.1rem",
  fontWeight: 600,
  letterSpacing: "0.06em",
  textTransform: "uppercase",
  color: "#9ca3af",
  marginBottom: "0.5rem",
};

const h1Style = {
  fontSize: "1.8rem",
  fontWeight: 700,
  marginBottom: "0.25rem",
};

const subtitleStyle = {
  color: "#9ca3af",
  fontSize: "0.95rem",
  marginBottom: "1.5rem",
};

const labelStyle = {
  display: "block",
  fontSize: "0.9rem",
  fontWeight: 500,
  marginBottom: "0.25rem",
};

const inputStyle = {
  width: "100%",
  padding: "0.6rem 0.75rem",
  borderRadius: "0.5rem",
  border: "1px solid #4b5563",
  backgroundColor: "#020617",
  color: "#e5e7eb",
  outline: "none",
  fontSize: "0.95rem",
};

const textareaStyle = {
  ...inputStyle,
  minHeight: "180px",
  fontFamily: "monospace",
  fontSize: "0.85rem",
  lineHeight: 1.4,
};

const buttonPrimary = {
  padding: "0.6rem 1.4rem",
  borderRadius: "999px",
  border: "none",
  background: "linear-gradient(135deg, #22c55e 0%, #22d3ee 40%, #6366f1 100%)",
  color: "#0b1120",
  fontWeight: 600,
  fontSize: "0.95rem",
  cursor: "pointer",
};

const buttonSecondary = {
  ...buttonPrimary,
  background: "transparent",
  border: "1px solid #4b5563",
  color: "#e5e7eb",
};

const buttonWarning = {
  ...buttonPrimary,
  background: "linear-gradient(135deg, #f59e0b 0%, #ef4444 100%)",
  color: "#fff",
};

const badgeStyle = (color) => ({
  display: "inline-flex",
  alignItems: "center",
  gap: "0.4rem",
  padding: "0.25rem 0.7rem",
  borderRadius: "999px",
  fontSize: "0.7rem",
  fontWeight: 600,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  backgroundColor: color === "green" ? "rgba(22,163,74,0.15)" : "rgba(59,130,246,0.18)",
  color: color === "green" ? "#4ade80" : "#60a5fa",
});

const pillStyle = {
  display: "inline-flex",
  alignItems: "center",
  gap: "0.35rem",
  padding: "0.25rem 0.6rem",
  borderRadius: "999px",
  fontSize: "0.75rem",
  backgroundColor: "rgba(31,41,55,0.9)",
  color: "#9ca3af",
};

const checkboxRowStyle = {
  display: "flex",
  flexWrap: "wrap",
  gap: "1.25rem",
  marginTop: "0.75rem",
};

const fieldRowStyle = {
  display: "flex",
  flexWrap: "wrap",
  gap: "1rem",
};

const fieldColStyle = {
  flex: 1,
  minWidth: "260px",
};

const infoRowStyle = {
  display: "flex",
  flexWrap: "wrap",
  justifyContent: "space-between",
  gap: "0.75rem",
  fontSize: "0.8rem",
  color: "#9ca3af",
};

const statusTag = (label, active, color) => ({
  padding: "0.25rem 0.7rem",
  borderRadius: "999px",
  fontSize: "0.7rem",
  fontWeight: 600,
  textTransform: "uppercase",
  border: `1px solid ${active ? color : "#4b5563"}`,
  color: active ? color : "#6b7280",
  backgroundColor: active ? `${color}15` : "transparent",
});

const logBoxStyle = {
  ...textareaStyle,
  minHeight: "160px",
  backgroundColor: "#020617",
};

const feedbackBoxStyle = {
  backgroundColor: "#1a1f35",
  borderRadius: "0.75rem",
  padding: "1rem",
  marginTop: "1rem",
  border: "1px solid rgba(251,191,36,0.3)",
};

const API_BASE = `http://${window.location.hostname}:8000`;

function App() {
  const [cveId, setCveId] = useState("CVE-2021-1234");
  const [llmInstructions, setLlmInstructions] = useState("");
  const [useRag, setUseRag] = useState(false);  // Option pour utiliser le RAG
  const [currentScenarioId, setCurrentScenarioId] = useState(null);

  const [generatedAttackScript, setGeneratedAttackScript] = useState("");
  const [generatedIdsRules, setGeneratedIdsRules] = useState("");

  const [editedAttackScript, setEditedAttackScript] = useState("");
  const [editedIdsRules, setEditedIdsRules] = useState("");

  const [feedbackComment, setFeedbackComment] = useState("");
  const [iterationCount, setIterationCount] = useState(0);

  const [scriptValidated, setScriptValidated] = useState(false);
  const [idsValidated, setIdsValidated] = useState(false);

  const [runOutput, setRunOutput] = useState("");
  const [loading, setLoading] = useState(false);
  const [feedbackLoading, setFeedbackLoading] = useState(false);
  const [execLoading, setExecLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");

  const [evaluation, setEvaluation] = useState(null);
  const [evaluating, setEvaluating] = useState(false);

  const hasGenerated = !!generatedAttackScript || !!generatedIdsRules;

  const handleGenerate = async (e) => {
    e.preventDefault();
    setError("");
    setInfo("");
    setRunOutput("");
    setGeneratedAttackScript("");
    setGeneratedIdsRules("");
    setEditedAttackScript("");
    setEditedIdsRules("");
    setScriptValidated(false);
    setIdsValidated(false);
    setIterationCount(0);
    setFeedbackComment("");
    setEvaluation(null);

    if (!cveId.trim()) {
      setError("Merci de renseigner un identifiant de CVE.");
      return;
    }

    setLoading(true);
    try {
      const scenarioRes = await fetch(`${API_BASE}/scenarios`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          cve_id: cveId.trim(),
          target_description:
            "VM vulnérable isolée dans le laboratoire PRAPP (description mockée, sera automatisée avec Proxmox).",
          nmap_output:
            "Mock Nmap output for isolated lab target (scan automatique à intégrer plus tard).",
          use_rag: useRag,  // Option RAG
        }),
      });

      if (!scenarioRes.ok) {
        throw new Error("Erreur lors de la création du scénario.");
      }
      const scenario = await scenarioRes.json();
      setCurrentScenarioId(scenario.id);

      const genRes = await fetch(
        `${API_BASE}/scenarios/${scenario.id}/generate`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            llm_instructions: llmInstructions.trim() || null,
          }),
        }
      );

      if (!genRes.ok) {
        throw new Error("Erreur lors de la génération script / IDS.");
      }

      const gen = await genRes.json();
      setGeneratedAttackScript(gen.attack_script || "");
      setGeneratedIdsRules(gen.ids_rules || "");
      setEditedAttackScript(gen.attack_script || "");
      setEditedIdsRules(gen.ids_rules || "");
      setIterationCount(1);

      setInfo("Génération terminée (Itération 1). Merci de relire et valider avant exécution, ou demander une correction au LLM.");
    } catch (err) {
      console.error(err);
      setError(err.message || "Erreur inconnue lors de la génération.");
    } finally {
      setLoading(false);
    }
  };

  const handleRequestFeedback = async () => {
    if (!currentScenarioId) return;
    if (!feedbackComment.trim()) {
      setError("Merci de fournir un commentaire pour le feedback au LLM.");
      return;
    }

    setError("");
    setInfo("");
    setFeedbackLoading(true);

    try {
      const res = await fetch(
        `${API_BASE}/scenarios/${currentScenarioId}/refine`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            current_attack_script: editedAttackScript,
            current_ids_rules: editedIdsRules,
            feedback: feedbackComment.trim(),
          }),
        }
      );

      if (!res.ok) {
        throw new Error("Erreur lors de la demande de raffinement au LLM.");
      }

      const refined = await res.json();
      setGeneratedAttackScript(refined.attack_script || "");
      setGeneratedIdsRules(refined.ids_rules || "");
      setEditedAttackScript(refined.attack_script || "");
      setEditedIdsRules(refined.ids_rules || "");
      setIterationCount(prev => prev + 1);
      setFeedbackComment("");
      setEvaluation(null);

      setInfo(`Raffinement terminé (Itération ${iterationCount + 1}). Le LLM a mis à jour les scripts selon vos retours.`);
    } catch (err) {
      console.error(err);
      setError(err.message || "Erreur lors du raffinement.");
    } finally {
      setFeedbackLoading(false);
    }
  };

  const handleSaveOverrides = async () => {
    if (!currentScenarioId) return;
    setError("");
    setInfo("");
    setSaving(true);
    try {
      const res = await fetch(
        `${API_BASE}/scenarios/${currentScenarioId}/override`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            attack_script: editedAttackScript,
            ids_rules: editedIdsRules,
          }),
        }
      );

      if (!res.ok) {
        throw new Error(
          "Impossible d'enregistrer les modifications sur le backend."
        );
      }

      setGeneratedAttackScript(editedAttackScript);
      setGeneratedIdsRules(editedIdsRules);
      setInfo("Modifications enregistrées côté orchestrateur.");
    } catch (err) {
      console.error(err);
      setError(
        err.message ||
        "Erreur lors de l'enregistrement des modifications sur le backend."
      );
    } finally {
      setSaving(false);
    }
  };

  const handleExecute = async () => {
    setError("");
    setInfo("");
    setRunOutput("");

    if (!currentScenarioId) {
      setError("Aucun scénario actif. Merci de générer à partir d'une CVE.");
      return;
    }
    if (!scriptValidated || !idsValidated) {
      setError(
        "Le script d'attaque et les règles IDS doivent être validés par un humain avant exécution."
      );
      return;
    }

    setExecLoading(true);
    try {
      await handleSaveOverrides();

      const res = await fetch(
        `${API_BASE}/runs/${currentScenarioId}/execute`,
        { method: "POST" }
      );

      if (!res.ok) {
        throw new Error("Erreur lors de l'exécution de la simulation.");
      }

      const run = await res.json();
      setRunOutput(
        `Attack success: ${run.attack_success}\n` +
        `Detected by IDS: ${run.detected_by_ids}\n\n` +
        `Logs:\n${run.raw_logs}`
      );
      setInfo("Simulation terminée. Les logs sont disponibles ci-dessous.");
    } catch (err) {
      console.error(err);
      setError(err.message || "Erreur inconnue pendant l'exécution.");
    } finally {
      setExecLoading(false);
    }
  };

  const handleEvaluate = async () => {
    if (!currentScenarioId) {
      setError("Aucun scénario actif.");
      return;
    }

    setEvaluating(true);
    setError("");
    setInfo("");

    try {
      const res = await fetch(
        `${API_BASE}/scenarios/${currentScenarioId}/evaluate`,
        { method: "POST" }
      );

      if (!res.ok) {
        throw new Error("Erreur lors de l'évaluation du code.");
      }

      const evalData = await res.json();
      setEvaluation(evalData);
      setInfo("Évaluation terminée avec succès !");
    } catch (err) {
      console.error(err);
      setError(err.message || "Erreur lors de l'évaluation.");
    } finally {
      setEvaluating(false);
    }
  };

  const ScoreGauge = ({ score, label }) => {
    const getColor = (score) => {
      if (score >= 80) return "#4ade80";
      if (score >= 60) return "#fbbf24";
      return "#ef4444";
    };

    const color = getColor(score);
    const percentage = score;

    return (
      <div style={{ textAlign: "center" }}>
        <div style={{ fontSize: "0.85rem", color: "#9ca3af", marginBottom: "0.5rem" }}>
          {label}
        </div>
        <div style={{
          position: "relative",
          width: "120px",
          height: "120px",
          margin: "0 auto"
        }}>
          <svg viewBox="0 0 36 36" style={{ transform: "rotate(-90deg)" }}>
            <path
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              fill="none"
              stroke="#1a1f35"
              strokeWidth="3"
            />
            <path
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              fill="none"
              stroke={color}
              strokeWidth="3"
              strokeDasharray={`${percentage}, 100`}
              strokeLinecap="round"
            />
          </svg>
          <div style={{
            position: "absolute",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            fontSize: "1.5rem",
            fontWeight: "bold",
            color: color
          }}>
            {score}<span style={{ fontSize: "1rem" }}>/100</span>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div style={containerStyle}>
      <header style={{ marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: "1rem" }}>
          <div>
            <div style={badgeStyle("blue")}>
              <span>PRAPP · Orchestrateur</span>
            </div>
            <h1 style={h1Style}>Assistant de pentest · LLM & IDS</h1>
            <p style={subtitleStyle}>
              Prototype avec résultats mockés. Nouvelles fonctionnalités : instructions LLM personnalisées + boucle de feedback pour auto-correction + évaluation qualité.
            </p>
          </div>
          <div style={{ textAlign: "right", minWidth: "180px" }}>
            <div style={pillStyle}>
              <span
                style={{
                  display: "inline-block",
                  width: "8px",
                  height: "8px",
                  borderRadius: "999px",
                  backgroundColor: "#22c55e",
                }}
              ></span>
              Backend en ligne
            </div>
          </div>
        </div>
      </header>

      {/* Étape 1 : saisie CVE & génération */}
      <section style={cardStyle}>
        <div style={{ marginBottom: "0.75rem" }}>
          <div style={sectionTitleStyle}>Étape 1 · Définir le scénario</div>
          <div style={infoRowStyle}>
            <span>Vous fournissez la CVE et optionnellement des instructions pour le LLM.</span>
            <span>
              <span style={statusTag("Génération", !!hasGenerated, "#38bdf8")}>
                {hasGenerated ? `Généré (It. ${iterationCount})` : "En attente"}
              </span>
            </span>
          </div>
        </div>

        <form onSubmit={handleGenerate} style={{ marginTop: "1rem" }}>
          <div style={{ marginBottom: "0.75rem" }}>
            <label style={labelStyle}>Identifiant CVE</label>
            <input
              type="text"
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder="Ex : CVE-2021-1234"
              style={inputStyle}
            />
          </div>

          <div style={{ marginBottom: "0.75rem" }}>
            <label style={labelStyle}>
              Instructions complémentaires pour le LLM (optionnel)
            </label>
            <textarea
              value={llmInstructions}
              onChange={(e) => setLlmInstructions(e.target.value)}
              placeholder="Ex : Utilise Python 3 uniquement, évite les dépendances externes, cible un serveur Apache 2.4..."
              style={{ ...inputStyle, minHeight: "80px", fontFamily: "inherit" }}
            />
          </div>

          {/* Option RAG */}
          <div style={{ marginBottom: "0.75rem" }}>
            <label style={{ fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={useRag}
                onChange={(e) => setUseRag(e.target.checked)}
                style={{ width: "18px", height: "18px", accentColor: "#22c55e" }}
              />
              <span style={{ fontWeight: 500 }}> Utiliser le RAG (Retrieval-Augmented Generation)</span>
            </label>
            <p style={{ fontSize: "0.8rem", color: "#9ca3af", marginTop: "0.25rem", marginLeft: "1.5rem" }}>
              Active la recherche dans la base de données NVD pour enrichir le contexte du LLM avec des informations techniques sur la CVE.
            </p>
          </div>

          <div
            style={{
              fontSize: "0.8rem",
              color: "#9ca3af",
              marginBottom: "0.9rem",
            }}
          >
            <strong>Backend :</strong> description de la cible et sortie Nmap sont actuellement
            des constantes mockées. Elles seront remplacées par des données réelles quand l'orchestrateur
            sera connecté aux VM sur Proxmox.
          </div>

          <button type="submit" disabled={loading} style={buttonPrimary}>
            {loading ? "Génération en cours..." : "Générer script & règles IDS"}
          </button>
        </form>
      </section>

      {/* Étape 2 : revue humaine & validation */}
      <section style={cardStyle}>
        <div style={{ marginBottom: "0.75rem" }}>
          <div style={sectionTitleStyle}>Étape 2 · Validation humaine & raffinement LLM</div>
          <div style={infoRowStyle}>
            <span>Vous pouvez modifier manuellement ou demander au LLM de corriger automatiquement.</span>
            <span>
              <span
                style={statusTag(
                  "Revue",
                  scriptValidated && idsValidated,
                  "#4ade80"
                )}
              >
                {scriptValidated && idsValidated
                  ? "Validé par un humain"
                  : "En attente de validation"}
              </span>
            </span>
          </div>
        </div>

        {!hasGenerated && (
          <p style={{ fontSize: "0.85rem", color: "#6b7280" }}>
            Aucune génération disponible. Merci de renseigner une CVE et d'exécuter l'étape 1.
          </p>
        )}

        {hasGenerated && (
          <>
            <div style={{ ...fieldRowStyle, marginTop: "0.75rem" }}>
              <div style={fieldColStyle}>
                <label style={labelStyle}>Script d'attaque (éditable)</label>
                <textarea
                  style={textareaStyle}
                  value={editedAttackScript}
                  onChange={(e) => setEditedAttackScript(e.target.value)}
                />
              </div>
              <div style={fieldColStyle}>
                <label style={labelStyle}>Règles IDS (éditables)</label>
                <textarea
                  style={textareaStyle}
                  value={editedIdsRules}
                  onChange={(e) => setEditedIdsRules(e.target.value)}
                />
              </div>
            </div>

            {/* Feedback au LLM */}
            <div style={feedbackBoxStyle}>
              <label style={{ ...labelStyle, color: "#fbbf24" }}>
                 Demander un raffinement au LLM
              </label>
              <p style={{ fontSize: "0.8rem", color: "#9ca3af", marginBottom: "0.5rem" }}>
                Si les scripts générés ne vous conviennent pas, décrivez ce qui doit être corrigé.
                Le LLM va analyser votre retour et régénérer les scripts.
              </p>
              <textarea
                value={feedbackComment}
                onChange={(e) => setFeedbackComment(e.target.value)}
                placeholder="Ex : Le script ne gère pas les erreurs de connexion, ajoute une vérification du port 443, les règles IDS sont trop permissives..."
                style={{ ...inputStyle, minHeight: "80px", fontFamily: "inherit", marginBottom: "0.75rem" }}
              />
              <button
                type="button"
                style={buttonWarning}
                onClick={handleRequestFeedback}
                disabled={feedbackLoading || !feedbackComment.trim()}
              >
                {feedbackLoading ? "Correction en cours..." : "Envoyer feedback au LLM"}
              </button>
            </div>

            <div style={checkboxRowStyle}>
              <label style={{ fontSize: "0.85rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                <input
                  type="checkbox"
                  checked={scriptValidated}
                  onChange={(e) => setScriptValidated(e.target.checked)}
                />
                Script d'attaque relu et validé par un humain.
              </label>
              <label style={{ fontSize: "0.85rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                <input
                  type="checkbox"
                  checked={idsValidated}
                  onChange={(e) => setIdsValidated(e.target.checked)}
                />
                Règles IDS relues et validées par un humain.
              </label>
            </div>

            <div style={{ marginTop: "0.9rem", display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
              <button
                type="button"
                style={buttonSecondary}
                onClick={handleSaveOverrides}
                disabled={saving}
              >
                {saving ? "Enregistrement..." : "Enregistrer les modifications dans l'orchestrateur"}
              </button>
            </div>
          </>
        )}
      </section>

      {/* Étape 3 : Évaluation de la qualité du code */}
      <section style={cardStyle}>
        <div style={{ marginBottom: "0.75rem" }}>
          <div style={sectionTitleStyle}>Étape 2.5 · Évaluation de la qualité</div>
          <div style={infoRowStyle}>
            <span>Évaluation automatique par LLM de la qualité du code généré</span>
            <span>
              <span
                style={statusTag(
                  "Évaluation",
                  !!evaluation,
                  "#a855f7"
                )}
              >
                {evaluation ? "Évalué" : "En attente"}
              </span>
            </span>
          </div>
        </div>

        {!hasGenerated && (
          <p style={{ fontSize: "0.85rem", color: "#6b7280" }}>
            Aucun code à évaluer. Merci de générer d'abord le script et les règles IDS.
          </p>
        )}

        {hasGenerated && !evaluation && (
          <button
            type="button"
            style={buttonPrimary}
            onClick={handleEvaluate}
            disabled={evaluating}
          >
            {evaluating ? "Évaluation en cours..." : "Évaluer la qualité du code"}
          </button>
        )}

        {evaluation && (
          <>
            <div style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
              gap: "1.5rem",
              marginTop: "1rem",
              marginBottom: "2rem"
            }}>
              <ScoreGauge score={evaluation.overall_score} label="Score Global" />
              <ScoreGauge score={evaluation.attack_script_score} label="Script d'Attaque" />
              <ScoreGauge score={evaluation.ids_rules_score} label="Règles IDS" />
            </div>

            <div style={{ ...fieldRowStyle, gap: "1rem" }}>
              <div style={fieldColStyle}>
                <label style={labelStyle}> Feedback - Script d'Attaque</label>
                <textarea
                  style={{ ...textareaStyle, minHeight: "200px", fontSize: "0.8rem" }}
                  value={evaluation.attack_feedback}
                  readOnly
                />
              </div>
              <div style={fieldColStyle}>
                <label style={labelStyle}> Feedback - Règles IDS</label>
                <textarea
                  style={{ ...textareaStyle, minHeight: "200px", fontSize: "0.8rem" }}
                  value={evaluation.ids_feedback}
                  readOnly
                />
              </div>
            </div>

            <div style={{ marginTop: "1rem" }}>
              <button
                type="button"
                style={buttonSecondary}
                onClick={handleEvaluate}
                disabled={evaluating}
              >
                {evaluating ? "Ré-évaluation..." : "Ré-évaluer le code"}
              </button>
            </div>
          </>
        )}
      </section>

      {/* Étape 4 : exécution de la simulation */}
      <section style={cardStyle}>
        <div style={{ marginBottom: "0.75rem" }}>
          <div style={sectionTitleStyle}>Étape 3 · Exécution contrôlée</div>
          <div style={infoRowStyle}>
            <span>
              L'exécution est bloquée tant que le script et les règles IDS n'ont pas été validés par
              un humain.
            </span>
            <span>
              <span
                style={statusTag(
                  "Simulation",
                  !!runOutput,
                  "#a855f7"
                )}
              >
                {runOutput ? "Simulation réalisée" : "En attente"}
              </span>
            </span>
          </div>
        </div>

        <div style={{ marginBottom: "0.9rem" }}>
          <button
            type="button"
            style={buttonPrimary}
            onClick={handleExecute}
            disabled={
              execLoading ||
              !currentScenarioId ||
              !hasGenerated ||
              !scriptValidated ||
              !idsValidated
            }
          >
            {execLoading ? "Simulation en cours..." : "Exécuter la simulation sur le lab"}
          </button>
        </div>

        {runOutput && (
          <>
            <label style={labelStyle}>Logs d'exécution & détection IDS</label>
            <textarea
              style={logBoxStyle}
              value={runOutput}
              readOnly
            />
          </>
        )}
      </section>

      {(error || info) && (
        <section style={{ marginTop: "0.75rem" }}>
          {error && (
            <div
              style={{
                backgroundColor: "rgba(239,68,68,0.12)",
                borderRadius: "0.75rem",
                padding: "0.6rem 0.8rem",
                border: "1px solid rgba(239,68,68,0.45)",
                fontSize: "0.85rem",
                marginBottom: "0.45rem",
              }}
            >
              <strong style={{ color: "#fca5a5" }}>Erreur : </strong>
              <span>{error}</span>
            </div>
          )}
          {info && (
            <div
              style={{
                backgroundColor: "rgba(56,189,248,0.12)",
                borderRadius: "0.75rem",
                padding: "0.6rem 0.8rem",
                border: "1px solid rgba(56,189,248,0.45)",
                fontSize: "0.85rem",
              }}
            >
              <strong style={{ color: "#7dd3fc" }}>Info : </strong>
              <span>{info}</span>
            </div>
          )}
        </section>
      )}
    </div>
  );
}

export default App;
