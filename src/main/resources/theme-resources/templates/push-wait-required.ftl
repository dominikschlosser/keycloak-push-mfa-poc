<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=((messagesPerField?has_content)!false) || (messageSummary??); section>
    <#if section = "header">
        ${msg("push-mfa-title")}
    <#elseif section = "form">
        <style>
            .kc-push-card {
                background: var(--pf-v5-global--BackgroundColor--100, #fff);
                border: 1px solid var(--pf-v5-global--BorderColor--100, #d2d2d2);
                border-radius: 4px;
                box-shadow: var(--pf-global--BoxShadow--md, 0 1px 2px rgba(0, 0, 0, 0.1));
                padding: 1.5rem;
                margin-top: 1.5rem;
            }

            .kc-push-actions {
                display: flex;
                gap: 0.75rem;
                flex-wrap: wrap;
                margin-top: 1.5rem;
            }

            .kc-push-hint {
                margin-top: 0.75rem;
                color: var(--pf-v5-global--Color--200, #6a6e73);
                font-size: 0.95rem;
            }

            .kc-push-countdown {
                text-align: center;
                font-size: 2rem;
                font-weight: bold;
                margin: 1.5rem 0;
                color: var(--pf-v5-global--Color--100, #151515);
            }

            .kc-push-countdown-label {
                font-size: 0.9rem;
                font-weight: normal;
                color: var(--pf-v5-global--Color--200, #6a6e73);
            }
        </style>

        <div class="${properties.kcContentWrapperClass!}">
            <div class="kc-push-card">
                <div class="alert alert-warning">
                    ${msg("push-mfa-wait-required-message")!"Too many unapproved challenges. Please wait before requesting a new one."}
                </div>
                <div class="kc-push-countdown">
                    <span id="countdown">${waitSeconds!0}</span>
                    <span class="kc-push-countdown-label">${msg("push-mfa-seconds-remaining")!"seconds remaining"}</span>
                </div>
                <p class="kc-push-hint">${msg("push-mfa-wait-required-hint")!"You can retry once the countdown reaches zero."}</p>
                <form id="kc-wait-form" action="${url.loginAction}" method="post" class="kc-push-actions">
                    <button id="retry-btn" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" type="submit"
                            name="retry" disabled>${msg("push-mfa-retry")!"Retry"}</button>
                </form>
            </div>
        </div>

        <script>
            (function() {
                var seconds = ${waitSeconds!0};
                var countdown = document.getElementById('countdown');
                var btn = document.getElementById('retry-btn');
                if (seconds > 0) {
                    var interval = setInterval(function() {
                        seconds--;
                        countdown.textContent = seconds;
                        if (seconds <= 0) {
                            clearInterval(interval);
                            btn.disabled = false;
                            btn.textContent = '${msg("push-mfa-retry-now")!"Retry Now"}';
                        }
                    }, 1000);
                } else {
                    btn.disabled = false;
                }
            })();
        </script>
    </#if>
</@layout.registrationLayout>
