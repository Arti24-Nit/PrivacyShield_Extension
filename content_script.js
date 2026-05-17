(function() {
  /**
   * ============================================================
   *  PRIVACY SHIELD — Advanced Fingerprinting Detection
   *  content_script.js  |  Manifest V2  |  ES2020+
   * ============================================================
   */

  browser.storage.local.get(['protectionSettings']).then((res) => {
    const settings = res.protectionSettings || { fingerprinting: true, strictFP: false };
    if (!settings.fingerprinting) return;

    const injection = `
      (function() {
        const strictMode = ${settings.strictFP};
        const detectedAPIs = new Set();
        const notifyExtension = (apiName, details) => {
          if (!detectedAPIs.has(apiName)) {
            detectedAPIs.add(apiName);
            window.postMessage({
              type: 'FINGERPRINTING_ATTEMPT',
              api: apiName,
              details: details
            }, '*');
          }
        };

        // Spoofing helpers
        const spoofValue = (val) => {
          if (!strictMode) return val;
          // Return a slightly modified value to break fingerprinting consistency
          if (typeof val === 'number') return val + (Math.random() * 0.01);
          return val;
        };

        // 1. Canvas Fingerprinting Detection
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function() {
          notifyExtension('Canvas.toDataURL', 'Access to canvas pixel data');
          return originalToDataURL.apply(this, arguments);
        };

        const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        CanvasRenderingContext2D.prototype.getImageData = function() {
          notifyExtension('Canvas.getImageData', 'Access to canvas pixel data');
          const data = originalGetImageData.apply(this, arguments);
          if (strictMode) {
            // Add slight noise to image data to break hashing
            data.data[0] = (data.data[0] + 1) % 256;
          }
          return data;
        };

        // 2. WebGL Fingerprinting Detection
        const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(parameter) {
          notifyExtension('WebGL.getParameter', 'Access to WebGL renderer info');
          const val = originalGetParameter.apply(this, arguments);
          return spoofValue(val);
        };

        // 3. Audio Fingerprinting Detection
        const originalCreateOscillator = (window.AudioContext || window.webkitAudioContext).prototype.createOscillator;
        (window.AudioContext || window.webkitAudioContext).prototype.createOscillator = function() {
          notifyExtension('AudioContext.createOscillator', 'Access to audio hardware signature');
          return originalCreateOscillator.apply(this, arguments);
        };

        // 4. Hardware Fingerprinting Detection
        const navProps = ['hardwareConcurrency', 'deviceMemory', 'platform', 'languages', 'doNotTrack'];
        navProps.forEach(prop => {
          try {
            const originalProp = navigator[prop];
            Object.defineProperty(navigator, prop, {
              get: function() {
                notifyExtension('Navigator.' + prop, 'Access to hardware/OS identifiers');
                if (strictMode) {
                  if (prop === 'hardwareConcurrency') return 4;
                  if (prop === 'deviceMemory') return 8;
                }
                return originalProp;
              }
            });
          } catch(e) {}
        });

        // 5. Battery API Detection
        if (navigator.getBattery) {
          const originalGetBattery = navigator.getBattery;
          navigator.getBattery = function() {
            notifyExtension('Navigator.getBattery', 'Access to battery level and status');
            return originalGetBattery.apply(this, arguments);
          };
        }

        // 6. Screen Fingerprinting Detection
        const screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
        screenProps.forEach(prop => {
          try {
            const originalProp = screen[prop];
            Object.defineProperty(screen, prop, {
              get: function() {
                notifyExtension('Screen.' + prop, 'Access to display resolution and color depth');
                return originalProp;
              }
            });
          } catch(e) {}
        });

        // 7. Font Fingerprinting (via getClientRects on large strings)
        const originalGetClientRects = Element.prototype.getClientRects;
        Element.prototype.getClientRects = function() {
          return originalGetClientRects.apply(this, arguments);
        };
      })();
    `;

    const script = document.createElement('script');
    script.textContent = injection;
    (document.head || document.documentElement).appendChild(script);
    script.remove();
  });

  // Listen for messages from the injected script
  window.addEventListener('message', (event) => {
    if (event.source !== window || !event.data || event.data.type !== 'FINGERPRINTING_ATTEMPT') {
      return;
    }

    // Send the detection to the background script
    browser.runtime.sendMessage({
      type: 'FINGERPRINTING_DETECTED',
      api: event.data.api,
      details: event.data.details,
      url: window.location.href
    });
  });

})();
