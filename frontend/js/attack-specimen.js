(function () {
    "use strict";

    const state = {
        sessions: [],
        selected: null,
        timer: null
    };

    const $ = (id) => document.getElementById(id);

    function text(id, value) {
        const el = $(id);
        if (el) el.textContent = value ?? "—";
    }

    function num(value, fallback = 0) {
        const n = Number(value);
        return Number.isFinite(n) ? n : fallback;
    }

    function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function riskLabel(score) {
        if (score >= 75) return "CRITICAL";
        if (score >= 50) return "HIGH";
        if (score >= 25) return "MEDIUM";
        return "LOW";
    }

    function setBar(id, value) {
        const el = $(id);
        if (!el) return;

        const n = Math.max(
            0,
            Math.min(100, num(value))
        );

        el.style.width = `${n}%`;
    }

    function render(session) {
        if (!session) {
            text("as-ip", "—");
            text("as-session", "—");
            text("as-service", "—");
            text("as-duration", "—");
            text("as-interactions", "—");

            text("as-risk", "—");
            text("as-risk-label", "NO DATA");

            text("as-response-risk", "—");
            text("as-profile", "—");
            text("as-transitions", "—");
            text("as-reward", "—");

            text("as-recon-value", "—");
            text("as-cred-value", "—");
            text("as-path-value", "—");
            text("as-payload-value", "—");

            setBar("as-risk-fill", 0);
            setBar("as-recon", 0);
            setBar("as-cred", 0);
            setBar("as-path", 0);
            setBar("as-payload", 0);

            return;
        }

        const risk = num(session.risk_score);

        const attacks = Array.isArray(session.attack_types)
            ? session.attack_types
            : [];

        const services = Array.isArray(session.fake_services)
            ? session.fake_services
            : [];

        const commands = Array.isArray(session.commands_issued)
            ? session.commands_issued
            : [];

        const payloads = Array.isArray(session.payload_hashes)
            ? session.payload_hashes
            : [];

        const ttp = session.ttp_fingerprint || {};
        const chain = session.attack_chain || {};

        /*
         * Identity
         */

        text(
            "as-ip",
            session.ip_address || "—"
        );

        text(
            "as-session",
            session.session_id || "—"
        );

        text(
            "as-service",
            services.length
                ? services.join(", ")
                : "—"
        );

        text(
            "as-duration",
            session.session_duration !== undefined
                ? `${num(session.session_duration).toFixed(1)}s`
                : "—"
        );

        text(
            "as-interactions",
            session.interaction_depth ?? "—"
        );

        /*
         * Threat posture
         */

        text(
            "as-risk",
            risk.toFixed(1)
        );

        text(
            "as-risk-label",
            riskLabel(risk)
        );

        setBar(
            "as-risk-fill",
            risk
        );

        /*
         * Behavioral activity
         *
         * These are based only on fields actually returned
         * by the backend. No fabricated ML scores.
         */

        const recon = num(
            session.fingerprinting_attempts
        ) > 0
            ? Math.min(
                100,
                session.fingerprinting_attempts * 25
            )
            : (
                chain.chain_name &&
                chain.chain_name
                    .toLowerCase()
                    .includes("recon")
                    ? 70
                    : 0
            );

        const credential = attacks.includes(
            "brute_force"
        )
            ? Math.min(
                100,
                Math.max(
                    60,
                    session.attack_count * 20
                )
            )
            : 0;

        const enumeration =
            commands.some(command =>
                /GET|LIST|ENUM|SCAN|WP-ADMIN/i
                    .test(command)
            )
                ? 70
                : 0;

        const payload = Math.min(
            100,
            num(session.download_attempts) * 25 +
            payloads.length * 20
        );

        setBar("as-recon", recon);
        setBar("as-cred", credential);
        setBar("as-path", enumeration);
        setBar("as-payload", payload);

        text(
            "as-recon-value",
            `${Math.round(recon)}%`
        );

        text(
            "as-cred-value",
            `${Math.round(credential)}%`
        );

        text(
            "as-path-value",
            `${Math.round(enumeration)}%`
        );

        text(
            "as-payload-value",
            `${Math.round(payload)}%`
        );

        /*
         * Adaptive response
         */

        text(
            "as-response-risk",
            risk.toFixed(1)
        );

        text(
            "as-profile",
            session.honeypot_state || "default"
        );

        text(
            "as-transitions",
            session.attack_chain_progress ?? 0
        );

        text(
            "as-reward",
            session.deception_score_avg !== undefined
                ? Number(
                    session.deception_score_avg
                ).toFixed(3)
                : "—"
        );

        /*
         * Attack progression
         */

        updateProgression(session);

        /*
         * Timeline
         */

        renderTimeline(session);
    }

    function updateProgression(session) {
        const flow = document.querySelector(".as-flow");

        if (!flow) return;

        const stage =
            session?.ttp_fingerprint?.attack_chain_stage ||
            "";

        const progress = num(
            session?.attack_chain_progress
        );

        const stages = [
            "ACCESS",
            "RECON",
            "ENUMERATION",
            "EXPLOIT",
            "ADAPT"
        ];

        flow.innerHTML = stages.map(
            (name, index) => {

                const active =
                    progress >= index + 1 ||
                    stage
                        .toUpperCase()
                        .includes(name);

                return `
                    <span class="${
                        active
                            ? "as-stage-active"
                            : ""
                    }">
                        ${name}
                    </span>
                    ${
                        index < stages.length - 1
                            ? "<b>→</b>"
                            : ""
                    }
                `;
            }
        ).join("");
    }

    function renderTimeline(session) {
        const timeline = $("as-timeline");

        if (!timeline) return;

        const events = [];

        /*
         * Session start
         */

        if (session.first_seen) {
            events.push({
                type: "SESSION START",
                time: session.first_seen,
                detail:
                    `${session.ip_address || "Unknown origin"} established a session`
            });
        }

        /*
         * Attack types
         */

        for (const attack of (
            session.attack_types || []
        )) {
            events.push({
                type: "ATTACK DETECTED",
                time: session.last_seen,
                detail: attack
            });
        }

        /*
         * Commands
         */

        for (const command of (
            session.commands_issued || []
        )) {
            events.push({
                type: "COMMAND / REQUEST",
                time: session.last_seen,
                detail: command
            });
        }

        /*
         * Deception state
         */

        if (session.honeypot_state) {
            events.push({
                type: "DECEPTION STATE",
                time: session.last_seen,
                detail:
                    `PRAETOR state: ${session.honeypot_state}`
            });
        }

        /*
         * TTP fingerprint
         */

        if (session.ttp_fingerprint) {
            const ttp = session.ttp_fingerprint;

            if (
                ttp.tool_signature ||
                ttp.timing_pattern ||
                ttp.attack_chain_stage
            ) {
                events.push({
                    type: "TTP FINGERPRINT",
                    time: session.last_seen,
                    detail:
                        [
                            ttp.tool_signature,
                            ttp.timing_pattern,
                            ttp.attack_chain_stage
                        ]
                        .filter(Boolean)
                        .join(" · ")
                });
            }
        }

        /*
         * Payloads
         */

        if (session.payload_hashes?.length) {
            events.push({
                type: "PAYLOAD CAPTURED",
                time: session.last_seen,
                detail:
                    `${session.payload_hashes.length} payload hash(es) recorded`
            });
        }

        /*
         * Risk
         */

        if (session.risk_score !== undefined) {
            events.push({
                type: "RISK ASSESSMENT",
                time: session.last_seen,
                detail:
                    `Risk score ${num(
                        session.risk_score
                    ).toFixed(1)} · ${riskLabel(
                        session.risk_score
                    )}`
            });
        }

        if (!events.length) {
            timeline.innerHTML = `
                <div class="as-empty">
                    No timeline events available.
                </div>
            `;
            return;
        }

        timeline.innerHTML = events.map(
            event => `
                <div class="as-timeline-event">

                    <div class="as-event-dot"></div>

                    <div class="as-event-content">

                        <div class="as-event-top">

                            <strong>
                                ${escapeHtml(
                                    event.type
                                )}
                            </strong>

                            <time>
                                ${escapeHtml(
                                    event.time
                                )}
                            </time>

                        </div>

                        <p>
                            ${escapeHtml(
                                event.detail
                            )}
                        </p>

                    </div>

                </div>
            `
        ).join("");
    }

    async function load() {
        if (
            !api ||
            typeof api.sessions !== "function"
        ) {
            console.error(
                "PRAETOR API client unavailable."
            );
            return;
        }

        try {
            const response =
                await api.sessions(50);

            let sessions = [];

            /*
             * Your backend currently returns:
             *
             * {
             *   value: [...],
             *   Count: 10
             * }
             */

            if (Array.isArray(response)) {
                sessions = response;
            } else if (
                response &&
                Array.isArray(response.value)
            ) {
                sessions = response.value;
            } else if (
                response &&
                Array.isArray(response.sessions)
            ) {
                sessions = response.sessions;
            }

            state.sessions = sessions;

            /*
             * Select the highest-risk specimen rather than
             * blindly selecting the newest zero-risk demo row.
             */

            const selected = [...sessions]
                .sort(
                    (a, b) =>
                        num(b.risk_score) -
                        num(a.risk_score)
                )[0];

            state.selected = selected || null;

            render(state.selected);

        } catch (error) {
            console.error(
                "Attack Specimen failed to load:",
                error
            );
        }
    }

    function start() {
        const refresh = $("as-refresh");

        if (refresh) {
            refresh.addEventListener(
                "click",
                load
            );
        }

        load();

        if (state.timer) {
            clearInterval(state.timer);
        }

        /*
         * Slower than Live Capture.
         * This is an investigation view, not a raw event feed.
         */

        state.timer = setInterval(
            load,
            15000
        );
    }

    window.PraetorAttackSpecimen = {
        start,
        refresh: load
    };

    if (
        document.readyState === "loading"
    ) {
        document.addEventListener(
            "DOMContentLoaded",
            () => {
                if (
                    $("attack-specimen-root")
                ) {
                    start();
                }
            }
        );
    } else if (
        $("attack-specimen-root")
    ) {
        start();
    }

})();
