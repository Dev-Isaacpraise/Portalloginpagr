/**
 * Client-side Controller for MFA Academic Credential Portal
 * ---------------------------------------------------------
 * Features:
 * 1. 6-digit OTP digit-box controller (auto-advance, backspace navigation, paste handler)
 * 2. RFC 6238 TOTP 30-second live epoch timer & animated circular progress
 * 3. Secret key clipboard copy utility
 * 4. Presentation / thesis defense live token helper
 */

document.addEventListener('DOMContentLoaded', () => {
  initOtpBoxes();
  initTotpCountdown();
  initCopyButtons();
});

/**
 * 1. 6-Digit OTP Spaced Box Input Controller
 */
function initOtpBoxes() {
  const otpGroup = document.querySelector('.otp-digit-group');
  const hiddenCodeInput = document.getElementById('hidden-otp-code');
  if (!otpGroup || !hiddenCodeInput) return;

  const boxes = Array.from(otpGroup.querySelectorAll('.otp-box'));
  if (boxes.length === 0) return;

  // Sync individual box values into the hidden form input
  function syncHiddenInput() {
    const fullCode = boxes.map((b) => b.value).join('');
    hiddenCodeInput.value = fullCode;

    // Auto-submit if all 6 digits entered
    const form = otpGroup ? otpGroup.closest('form') : null;
    if (fullCode.length === 6 && form && form.dataset.autoSubmit === 'true') {
      form.submit();
    }
  }

  boxes.forEach((box, index) => {
    // Focus first box initially if empty
    if (index === 0 && !box.value) {
      setTimeout(() => box.focus(), 150);
    }

    box.addEventListener('input', (e) => {
      const inputEl = e.target;
      const val = inputEl.value.replace(/[^0-9]/g, '');
      inputEl.value = val ? val.slice(-1) : '';

      if (inputEl.value && index < boxes.length - 1) {
        boxes[index + 1].focus();
        boxes[index + 1].select();
      }
      syncHiddenInput();
    });

    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace') {
        if (!box.value && index > 0) {
          boxes[index - 1].focus();
          boxes[index - 1].value = '';
          syncHiddenInput();
        }
      } else if (e.key === 'ArrowLeft' && index > 0) {
        boxes[index - 1].focus();
      } else if (e.key === 'ArrowRight' && index < boxes.length - 1) {
        boxes[index + 1].focus();
      }
    });

    // Handle full 6-digit paste
    box.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasteData = (e.clipboardData || window.clipboardData)?.getData('text') || '';
      const cleanDigits = pasteData.replace(/[^0-9]/g, '').slice(0, 6);

      if (cleanDigits.length > 0) {
        cleanDigits.split('').forEach((char, i) => {
          if (boxes[i]) {
            boxes[i].value = char;
          }
        });
        const nextIndex = Math.min(cleanDigits.length, boxes.length - 1);
        boxes[nextIndex].focus();
        syncHiddenInput();
      }
    });
  });

  // Presentation helper: Fill simulated code
  const fillBtn = document.getElementById('btn-fill-simulated-token');
  if (fillBtn) {
    fillBtn.addEventListener('click', async () => {
      try {
        fillBtn.innerText = 'Fetching...';
        const ticketInput = document.getElementById('mfa-ticket');
        const urlParams = new URLSearchParams(window.location.search);
        const ticketVal = (ticketInput && ticketInput.value) || urlParams.get('ticket') || '';
        const queryUrl = '/api/mfa/epoch-time' + (ticketVal ? `?ticket=${encodeURIComponent(ticketVal)}` : '');
        const res = await fetch(queryUrl);
        const data = await res.json();
        if (data.simulatedCode && data.simulatedCode.length === 6) {
          data.simulatedCode.split('').forEach((digit, i) => {
            if (boxes[i]) boxes[i].value = digit;
          });
          syncHiddenInput();
          fillBtn.innerText = 'Filled ' + data.simulatedCode;
          setTimeout(() => {
            fillBtn.innerText = 'Use Current Token (Test Helper)';
          }, 2000);
        } else {
          fillBtn.innerText = 'Code unavailable';
        }
      } catch (e) {
        fillBtn.innerText = 'Error fetching code';
      }
    });
  }
}

/**
 * 2. RFC 6238 Time-based Countdown & Progress Indicator
 */
function initTotpCountdown() {
  const timerContainer = document.querySelector('.totp-timer-bar');
  if (!timerContainer) return;

  const countdownText = document.getElementById('totp-countdown-seconds');
  const progressCircle = document.getElementById('totp-progress-circle');
  const radius = 9; // circle r=9
  const circumference = 2 * Math.PI * radius;

  if (progressCircle) {
    progressCircle.style.strokeDasharray = `${circumference}`;
  }

  function updateTimer() {
    const epochSeconds = Math.floor(Date.now() / 1000);
    const step = 30;
    const timeRemaining = step - (epochSeconds % step);

    if (countdownText) {
      countdownText.textContent = `${timeRemaining}s`;
    }

    if (progressCircle) {
      const offset = circumference - (timeRemaining / step) * circumference;
      progressCircle.style.strokeDashoffset = `${offset}`;

      // Warn when <= 5 seconds remain
      if (timeRemaining <= 5) {
        progressCircle.classList.add('expiring');
      } else {
        progressCircle.classList.remove('expiring');
      }
    }
  }

  updateTimer();
  setInterval(updateTimer, 1000);
}

/**
 * 3. Secret Key Copy Utility
 */
function initCopyButtons() {
  const copyBtn = document.getElementById('btn-copy-secret');
  const secretTextEl = document.getElementById('raw-secret-key');

  if (copyBtn && secretTextEl) {
    copyBtn.addEventListener('click', async () => {
      const textToCopy = secretTextEl.textContent ? secretTextEl.textContent.trim() : '';
      try {
        await navigator.clipboard.writeText(textToCopy);
        const originalText = copyBtn.textContent;
        copyBtn.textContent = 'Copied!';
        copyBtn.style.backgroundColor = '#059669';
        copyBtn.style.color = '#FFFFFF';

        setTimeout(() => {
          copyBtn.textContent = originalText;
          copyBtn.style.backgroundColor = '';
          copyBtn.style.color = '';
        }, 2000);
      } catch (err) {
        // Fallback for iframe clipboard restrictions
        const textarea = document.createElement('textarea');
        textarea.value = textToCopy;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        copyBtn.textContent = 'Copied!';
        setTimeout(() => {
          copyBtn.textContent = 'Copy';
        }, 2000);
      }
    });
  }
}

/**
 * 4. Iframe Token Continuity
 * Ensures seamless navigation in third-party iframe contexts (e.g. AI Studio preview)
 */
(function initSessionPersistence() {
  try {
    const params = new URLSearchParams(window.location.search);
    const authToken = params.get('auth_token');
    if (authToken) {
      sessionStorage.setItem('ful_portal_auth_token', authToken);
    }
    const storedToken = sessionStorage.getItem('ful_portal_auth_token');
    if (storedToken && window.location.pathname.startsWith('/dashboard') && !params.get('auth_token')) {
      // Append token to internal dashboard links
      document.querySelectorAll('a[href^="/dashboard"]').forEach(link => {
        const url = new URL(link.href, window.location.origin);
        if (!url.searchParams.has('auth_token')) {
          url.searchParams.set('auth_token', storedToken);
          link.href = url.pathname + url.search;
        }
      });
    }
  } catch (e) {
    // Graceful fallback
  }
})();

