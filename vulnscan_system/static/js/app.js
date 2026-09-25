(function () {
    "use strict";

    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    document.querySelectorAll(".auth-transition").forEach((link) => {
        link.addEventListener("click", (event) => {
            if (prefersReducedMotion) return;
            event.preventDefault();
            document.body.classList.add("auth-page-leaving");
            window.setTimeout(() => { window.location.href = link.href; }, 500);
        });
    });

    document.querySelectorAll("[data-auth-form]").forEach((form) => {
        form.addEventListener("submit", (event) => {
            if (prefersReducedMotion || form.dataset.submitting === "true") return;
            event.preventDefault();
            form.dataset.submitting = "true";
            document.body.classList.add("auth-page-leaving");
            const loader = document.querySelector(".auth-loader");
            const loaderText = loader?.querySelector("strong");
            if (loader) loader.classList.add("is-visible");
            const stages = ["Initializing secure access...", "Scanning credentials...", "Verifying access...", "Access granted."];
            let stage = 0;
            const timer = window.setInterval(() => {
                stage += 1;
                if (loaderText) loaderText.textContent = stages[Math.min(stage, stages.length - 1)];
                if (stage >= stages.length - 1) window.clearInterval(timer);
            }, 380);
            window.setTimeout(() => form.submit(), 1500);
        });
    });

    document.querySelectorAll(".auth-card input").forEach((input) => {
        input.addEventListener("focus", () => input.closest("label")?.classList.add("is-focused"));
        input.addEventListener("blur", () => input.closest("label")?.classList.remove("is-focused"));
    });

    document.querySelectorAll(".auth-card .btn-primary").forEach((button) => {
        button.addEventListener("click", (event) => {
            if (prefersReducedMotion) return;
            const ripple = document.createElement("span");
            ripple.className = "button-ripple";
            const rect = button.getBoundingClientRect();
            ripple.style.left = `${event.clientX - rect.left}px`;
            ripple.style.top = `${event.clientY - rect.top}px`;
            button.appendChild(ripple);
            ripple.addEventListener("animationend", () => ripple.remove(), { once: true });
        });
    });

    document.querySelectorAll(".logout-trigger").forEach((button) => {
        button.closest("form")?.addEventListener("submit", (event) => {
            if (prefersReducedMotion || button.dataset.submitting === "true") return;
            event.preventDefault();
            button.dataset.submitting = "true";
            const form = button.closest("form");
            const overlay = document.getElementById("logout-transition");
            const particleRoot = overlay?.querySelector(".logout-particles");
            if (!overlay) { form.submit(); return; }

            for (let index = 0; index < 64; index += 1) {
                const particle = document.createElement("i");
                const angle = Math.random() * Math.PI * 2;
                const distance = 120 + Math.random() * 280;
                particle.style.setProperty("--x", `${Math.cos(angle) * distance}px`);
                particle.style.setProperty("--y", `${Math.sin(angle) * distance}px`);
                particle.style.setProperty("--delay", `${Math.random() * 0.35}s`);
                particleRoot?.appendChild(particle);
            }
            overlay.classList.add("is-visible");
            window.setTimeout(() => form.submit(), 1900);
        });
    });

    /* ---------------------------------------------------------------
       Mobile nav toggle
       --------------------------------------------------------------- */
    const navToggle = document.querySelector(".nav-toggle");
    const nav = document.querySelector(".topbar nav");
    if (navToggle && nav) {
        navToggle.addEventListener("click", () => {
            const open = nav.classList.toggle("nav-open");
            navToggle.setAttribute("aria-expanded", String(open));
        });
    }

    /* ---------------------------------------------------------------
       Toast notifications
       --------------------------------------------------------------- */
    let toastContainer = document.getElementById("toast-container");
    if (!toastContainer) {
        toastContainer = document.createElement("div");
        toastContainer.id = "toast-container";
        document.body.appendChild(toastContainer);
    }

    window.showToast = function (message, timeout = 5000) {
        const toast = document.createElement("div");
        toast.className = "toast";
        toast.textContent = message;
        toastContainer.appendChild(toast);
        setTimeout(() => {
            toast.classList.add("toast-exit");
            toast.addEventListener("animationend", () => toast.remove(), { once: true });
        }, timeout);
    };

    /* Auto-dismiss server-rendered Django messages after a few seconds */
    document.querySelectorAll(".messages .message").forEach((msg) => {
        setTimeout(() => {
            if (prefersReducedMotion) { msg.remove(); return; }
            msg.style.transition = "opacity 0.3s ease, transform 0.3s ease";
            msg.style.opacity = "0";
            msg.style.transform = "translateY(-4px)";
            setTimeout(() => msg.remove(), 320);
        }, 6000);
    });

    /* ---------------------------------------------------------------
       Stat value count-up (dashboard)
       --------------------------------------------------------------- */
    function animateCountUp(el) {
        const target = parseFloat(el.dataset.countTo ?? el.textContent);
        if (Number.isNaN(target) || prefersReducedMotion) return;
        const isDecimal = String(el.dataset.countTo ?? "").includes(".");
        const duration = 700;
        const start = performance.now();

        function frame(now) {
            const progress = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            const value = target * eased;
            el.textContent = isDecimal ? value.toFixed(1) : Math.round(value).toLocaleString();
            if (progress < 1) requestAnimationFrame(frame);
            else el.textContent = isDecimal ? target.toFixed(1) : target.toLocaleString();
        }
        requestAnimationFrame(frame);
    }

    document.querySelectorAll(".stat-value[data-count-to]").forEach(animateCountUp);

    /* ---------------------------------------------------------------
       Live scan-status polling (job_detail page)
       Reads #scan-status-root[data-job-id][data-status][data-status-url]
       and polls until the job leaves QUEUED/RUNNING, then reloads once
       to render the final host/port/finding tables.
       --------------------------------------------------------------- */
    const statusRoot = document.getElementById("scan-status-root");
    if (statusRoot) {
        const jobId = statusRoot.dataset.jobId;
        const statusUrl = statusRoot.dataset.statusUrl;
        let currentStatus = statusRoot.dataset.status;
        const badge = document.getElementById("live-status-badge");
        const banner = document.getElementById("live-banner");
        const hostCountEl = document.getElementById("live-host-count");
        const progressBar = document.getElementById("scan-progress-bar");
        const progressValue = document.getElementById("scan-progress-value");
        const progressTrack = document.querySelector(".scan-progress-track");
        const progressPanel = document.getElementById("scan-progress-panel");
        const progressStatus = document.getElementById("scan-progress-status");

        const ACTIVE_STATES = ["QUEUED", "RUNNING"];

        function poll() {
            if (!ACTIVE_STATES.includes(currentStatus)) return;
            fetch(statusUrl, { headers: { "X-Requested-With": "XMLHttpRequest" } })
                .then((r) => r.json())
                .then((data) => {
                    if (hostCountEl) hostCountEl.textContent = data.host_count;
                    const progress = Math.max(0, Math.min(100, Number(data.progress) || 0));
                    const currentProgress = Number(progressValue?.textContent.replace("%", "")) || 0;
                    if (progressBar) {
                        progressBar.style.width = progress + "%";
                        progressBar.animate(
                            [{ width: currentProgress + "%" }, { width: progress + "%" }],
                            { duration: 700, easing: "ease-out", fill: "forwards" }
                        );
                    }
                    if (progressValue) progressValue.textContent = progress + "%";
                    if (progressTrack) progressTrack.setAttribute("aria-valuenow", String(progress));
                    if (data.status !== currentStatus) {
                        currentStatus = data.status;
                        if (!ACTIVE_STATES.includes(currentStatus)) {
                            const label = currentStatus === "COMPLETED" ? "Scan complete" : "Scan " + data.status_display.toLowerCase();
                            window.showToast(label + " — refreshing results…", 2500);
                            if (banner) banner.classList.remove("is-scanning");
                            if (progressPanel) progressPanel.classList.remove("is-active");
                            if (progressStatus) progressStatus.textContent = currentStatus === "COMPLETED" ? "Scan complete" : "Scan stopped";
                            setTimeout(() => window.location.reload(), 900);
                            return;
                        }
                    }
                    setTimeout(poll, 4000);
                })
                .catch(() => setTimeout(poll, 6000));
        }

        if (ACTIVE_STATES.includes(currentStatus)) {
            setTimeout(poll, 4000);
        }
    }
})();
