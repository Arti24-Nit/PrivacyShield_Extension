document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const trustScoreEl = document.getElementById('trustScore');
  const trustStatusEl = document.getElementById('trustStatus');
  const currentDomainEl = document.getElementById('currentDomain');
  const currentDomainSmallEl = document.getElementById('currentDomainSmall');
  const totalBlockedCountEl = document.getElementById('totalBlockedCount');
  const activeTrackerListEl = document.getElementById('activeTrackerList');
  const activityListEl = document.getElementById('activityList');
  const inspectorBodyEl = document.getElementById('inspectorBody');
  const manualColHeader = document.getElementById('manualColHeader');
  const insightsContentEl = document.getElementById('insightsContent');
  const trackerSearchInput = document.getElementById('trackerSearch');
  const whitelistListEl = document.getElementById('whitelistList');
  const trustCurrentSiteBtn = document.getElementById('trustCurrentSiteBtn');
  const activeTabNameEl = document.getElementById('activeTabName');
  
  const toggleAdBlocking = document.getElementById('toggleAdBlocking');
  const toggleSocialTrackers = document.getElementById('toggleSocialTrackers');
  const toggleFingerprinting = document.getElementById('toggleFingerprinting');
  const historyPath = document.querySelector('.mini-line-graph path');

  const gaugeCanvas = document.getElementById('trustGauge');
  const donutCanvas = document.getElementById('trackerDonut');
  
  // Popups
  const balancedModePopup = document.getElementById('balancedModePopup');
  const closePopupBtn = document.getElementById('closePopup');
  
  const navItems = document.querySelectorAll('.nav-item');
  const tabContents = document.querySelectorAll('.tab-content');
  const modeCards = document.querySelectorAll('.mode-card');

  // Advanced Toggles
  const blockCookiesToggle = document.getElementById('blockCookies');
  const showNotificationsToggle = document.getElementById('showNotifications');

  // State
  let lastStats = { statusColor: null };
  let searchTerm = '';

  // Canvas Drawing Helpers
  const drawGauge = (score) => {
    const ctx = gaugeCanvas.getContext('2d');
    const x = gaugeCanvas.width / 2;
    const y = 140; 
    const radius = 100; 
    ctx.clearRect(0, 0, gaugeCanvas.width, gaugeCanvas.height);
    
    ctx.beginPath();
    ctx.arc(x, y, radius, Math.PI, 2 * Math.PI);
    ctx.lineWidth = 10;
    ctx.strokeStyle = '#E2E8F0'; // Softer light grey for the track
    ctx.stroke();

    const gradient = ctx.createLinearGradient(0, 0, gaugeCanvas.width, 0);
    gradient.addColorStop(0, '#4F46E5'); // Indigo
    gradient.addColorStop(1, '#06B6D4'); // Cyan

    const endAngle = Math.PI + (score / 100) * Math.PI;
    ctx.beginPath();
    ctx.arc(x, y, radius, Math.PI, endAngle);
    ctx.lineWidth = 10;
    ctx.strokeStyle = gradient;
    ctx.lineCap = 'round';
    ctx.stroke();

    ctx.shadowBlur = 8; 
    let glowColor = lastStats.statusColor;
    if (!glowColor) {
      if (score >= 90) glowColor = '#059669'; // Emerald
      else if (score >= 70) glowColor = '#10B981'; // Green
      else if (score >= 50) glowColor = '#F59E0B'; // Amber
      else glowColor = '#EF4444'; // Red
    }
    ctx.shadowColor = glowColor;
    ctx.stroke();
    ctx.shadowBlur = 0;
  };

  const drawDonut = (data) => {
    const ctx = donutCanvas.getContext('2d');
    const x = donutCanvas.width / 2;
    const y = donutCanvas.height / 2;
    const radius = 65;
    const innerRadius = 50;
    ctx.clearRect(0, 0, donutCanvas.width, donutCanvas.height);
    
    let startAngle = -Math.PI / 2;
    // Palette: Cyan, Purple, Emerald, Indigo, Amber, Pink
    const colors = ['#06B6D4', '#8B5CF6', '#059669', '#4F46E5', '#F59E0B', '#EC4899'];
    const total = data.reduce((a, b) => a + b, 0) || 1;

    data.forEach((val, i) => {
      const sliceAngle = (val / total) * 2 * Math.PI;
      ctx.beginPath();
      ctx.arc(x, y, radius, startAngle, startAngle + sliceAngle);
      ctx.arc(x, y, innerRadius, startAngle + sliceAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = colors[i];
      ctx.fill();
      startAngle += sliceAngle;
    });
  };

  // Whitelist Management
  const getWhitelist = () => {
    return browser.storage.local.get(['whitelist']).then(res => res.whitelist || []);
  };

  const setWhitelist = (list) => {
    return browser.storage.local.set({ whitelist: list }).then(() => {
      browser.runtime.sendMessage({ command: 'updateWhitelist', whitelist: list });
    });
  };

  const renderWhitelist = () => {
    browser.storage.local.get(['whitelist']).then(res => {
      const whitelist = res.whitelist || [];
      whitelistListEl.innerHTML = '';

      if (whitelist.length === 0) {
        whitelistListEl.innerHTML = `
          <div class="empty-whitelist-msg">
            <svg viewBox="0 0 24 24" width="48" height="48" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round" class="empty-whitelist-icon"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>
            <p>No sites whitelisted yet. Your protection is active everywhere!</p>
          </div>
        `;
        return;
      }

      whitelist.forEach(domain => {
        const li = document.createElement('li');
        li.className = 'whitelist-item';
        li.innerHTML = `
          <div class="whitelist-item-info">
            <div class="site-icon-box">
              <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            </div>
            <span class="site-domain-name">${domain}</span>
          </div>
          <button class="remove-btn" data-domain="${domain}">Remove</button>
        `;
        whitelistListEl.appendChild(li);
      });

      // Add event listeners to remove buttons
      document.querySelectorAll('.remove-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const domainToRemove = e.target.getAttribute('data-domain');
          toggleWhitelist(domainToRemove);
        });
      });
    });
  };

  const toggleWhitelist = (domain) => {
    return getWhitelist().then(list => {
      let updated;
      if (list.includes(domain)) {
        updated = list.filter(d => d !== domain);
      } else {
        updated = [...list, domain];
      }
      return setWhitelist(updated).then(() => {
        renderWhitelist();
      });
    });
  };

  trustCurrentSiteBtn.addEventListener('click', () => {
    browser.tabs.query({ active: true, currentWindow: true }).then(tabs => {
      if (tabs[0]) {
        try {
          const url = new URL(tabs[0].url);
          const domain = url.hostname;
          if (domain && domain !== 'newtab') {
            toggleWhitelist(domain);
          }
        } catch (e) {
          console.error("Invalid URL for whitelisting", e);
        }
      }
    });
  });

  // Tab Switching Logic
  const switchTab = (tabId) => {
    navItems.forEach(item => {
      if (item.getAttribute('data-tab') === tabId) item.classList.add('active');
      else item.classList.remove('active');
    });

    // Special case for the Activity tab name
    if (tabId === 'activity') {
      activeTabNameEl.textContent = 'TRACKER ACTIVITY';
    } else {
      activeTabNameEl.textContent = tabId.toUpperCase();
    }

    if (tabId === 'sites') {
      renderWhitelist();
    }

    if (tabId === 'insights') {
      updateInsights();
    }

    tabContents.forEach(content => {
      content.style.opacity = '0';
      setTimeout(() => {
        if (content.id === `${tabId}Tab`) {
          content.classList.add('active');
          setTimeout(() => content.style.opacity = '1', 50);
        } else {
          content.classList.remove('active');
        }
      }, 200);
    });
  };

  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      const tabId = item.getAttribute('data-tab');
      if (tabId) {
        e.preventDefault();
        switchTab(tabId);
      }
    });
  });

  // Mode Selection Logic
  modeCards.forEach(card => {
    card.addEventListener('click', () => {
      const mode = card.getAttribute('data-mode');
      
      // If Balanced mode, show the categorization popup
      if (mode === 'balanced') {
        balancedModePopup.classList.remove('hidden');
      }

      // If Aggressive mode, set all protection toggles to ON and disable them
      if (mode === 'aggressive') {
        toggleAdBlocking.checked = true;
        toggleSocialTrackers.checked = true;
        toggleFingerprinting.checked = true;
        // Also set advanced settings
        blockCookiesToggle.checked = true;
        
        // Save these settings
        const settings = {
          adBlocking: true,
          socialTrackers: true,
          fingerprinting: true,
          strictFP: true // Still pass it to background for consistency, though UI is gone
        };
        browser.runtime.sendMessage({ command: 'updateSettings', settings });
        browser.storage.local.set({ blockCookies: true });
      }

      browser.storage.local.set({ privacyMode: mode });
      browser.runtime.sendMessage({ command: 'setMode', mode: mode });
      updateModeUI(mode);
    });
  });

  closePopupBtn.addEventListener('click', () => {
    balancedModePopup.classList.add('hidden');
  });

  // Close popup when clicking outside
  balancedModePopup.addEventListener('click', (e) => {
    if (e.target === balancedModePopup) {
      balancedModePopup.classList.add('hidden');
    }
  });

  const updateModeUI = (activeMode) => {
    modeCards.forEach(card => {
      const cardMode = card.getAttribute('data-mode');
      if (cardMode === activeMode) {
        card.classList.add('active');
      } else {
        card.classList.remove('active');
      }
    });

    // Disable/Enable toggles based on mode
    const isAggressive = activeMode === 'aggressive';
    const togglesToDisable = [
      toggleAdBlocking, 
      toggleSocialTrackers, 
      toggleFingerprinting, 
      blockCookiesToggle
    ];

    togglesToDisable.forEach(toggle => {
      toggle.disabled = isAggressive;
      if (isAggressive) toggle.checked = true; // Force ON in Aggressive mode
      
      const toggleItem = toggle.closest('.toggle-item');
      if (toggleItem) {
        if (isAggressive) toggleItem.classList.add('disabled');
        else toggleItem.classList.remove('disabled');
      }
    });
  };

  // Data Binding & UI Updates
  const updateUI = (stats) => {
    lastStats = stats;
    const score = stats.trustScore !== undefined ? stats.trustScore : 100;
    trustScoreEl.textContent = score;
    
    // New status logic as requested
    let statusLabel = '';
    let statusColor = '';
    let statusClass = '';

    if (score >= 90) {
      statusLabel = '(SECURE)';
      statusColor = '#00ff88';
      statusClass = 'status-secure';
    } else if (score >= 70) {
      statusLabel = '(SAFE)';
      statusColor = '#a3e635';
      statusClass = 'status-safe';
    } else if (score >= 50) {
      statusLabel = '(CAUTION)';
      statusColor = '#fbbf24';
      statusClass = 'status-caution';
    } else {
      statusLabel = '(HIGH RISK)';
      statusColor = '#f15bb5';
      statusClass = 'status-risk';
    }

    trustStatusEl.textContent = statusLabel;
    trustStatusEl.style.color = statusColor;
    trustStatusEl.className = statusClass;
    
    // Update shadow color for gauge
    lastStats.statusColor = statusColor;

    drawGauge(score);
    updateModeUI(stats.mode);

    // Update Domain
    browser.tabs.query({ active: true, currentWindow: true }).then(tabs => {
      if (tabs[0]) {
        const url = new URL(tabs[0].url);
        const domain = url.hostname;
        currentDomainEl.textContent = domain;
        if (currentDomainSmallEl) currentDomainSmallEl.textContent = domain;

        // Whitelist override: Force 100% trusted visuals
        browser.storage.local.get(['whitelist']).then(res => {
          const wl = res.whitelist || [];
          if (wl.includes(domain)) {
            trustScoreEl.textContent = 100;
            trustStatusEl.textContent = '(TRUSTED)';
            trustStatusEl.style.color = '#00ff88';
            trustStatusEl.className = 'status-secure';
            lastStats.statusColor = '#00ff88';
            drawGauge(100);
          }
        });
      }
    });

    totalBlockedCountEl.textContent = stats.totalTrackers || 0;
    
    // Donut Chart Update
    if (stats.categories) {
      const breakdown = [
        stats.categories.Advertising || 0,
        stats.categories.Analytics || 0,
        stats.categories.Social || 0,
        stats.categories.Cookies || 0,
        stats.categories.Fingerprinting || 0,
        stats.categories.Others || 0
      ];
      drawDonut(breakdown);

      // Update Legend Counts
      document.getElementById('count-adv').textContent = stats.categories.Advertising || 0;
      document.getElementById('count-ana').textContent = stats.categories.Analytics || 0;
      document.getElementById('count-soc').textContent = stats.categories.Social || 0;
      document.getElementById('count-cook').textContent = stats.categories.Cookies || 0;
      document.getElementById('count-fin').textContent = stats.categories.Fingerprinting || 0;
      document.getElementById('count-oth').textContent = stats.categories.Others || 0;
    }

    // Inspector Table Update
    updateInspectorTable();

    // Recent Activity Update
    activityListEl.innerHTML = '';
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    // Use the blockedRequests from background script for recent activity as well
    if (stats.blockedRequests && stats.blockedRequests.length > 0) {
      // Show last 5 blocked requests
      [...stats.blockedRequests].reverse().slice(0, 5).forEach(req => {
        const li = document.createElement('li');
        li.className = 'activity-item';
        li.innerHTML = `
          <div class="activity-icon blocked-icon"></div>
          <div class="activity-text">
            <span class="activity-title">Blocked ${req.type} on ${req.domain}</span>
            <span class="activity-domain">${req.domain}</span>
          </div>
          <span class="activity-time">${req.timestamp}</span>
        `;
        activityListEl.appendChild(li);
      });
    } else {
      activityListEl.innerHTML = '<li class="empty-state">No recent activity</li>';
    }

    // Update Threat History Graph
    if (stats.history && historyPath) {
      const maxVal = Math.max(...stats.history, 10); // Minimum scale
      const points = stats.history.map((val, i) => {
        const x = (i / 6) * 300;
        const y = 80 - (val / maxVal) * 60;
        return `${x},${y}`;
      });
      historyPath.setAttribute('d', `M${points.join(' L')}`);
    }

    // Update Protection Toggles
    if (stats.protectionSettings) {
      toggleAdBlocking.checked = stats.protectionSettings.adBlocking;
      toggleSocialTrackers.checked = stats.protectionSettings.socialTrackers;
      toggleFingerprinting.checked = stats.protectionSettings.fingerprinting;
      // Note: blockCookies and showNotifications are handled separately via storage
    }

    // Update Insights if tab is active
    const activeTab = document.querySelector('.nav-item.active').getAttribute('data-tab');
    if (activeTab === 'insights') {
      updateInsights();
    }
  };

  const updateInsights = () => {
    if (!lastStats || !lastStats.categories) return;

    insightsContentEl.innerHTML = '';
    const cats = lastStats.categories;
    const insights = [];

    // 1. Fingerprinting Insight
    if (cats.Fingerprinting > 0) {
      insights.push({
        type: 'fin',
        title: 'Fingerprinting Protection',
        desc: 'Why block Fingerprinting? Because it creates a unique ID for your device that stays even if you clear cookies.',
        icon: '<svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"></path><circle cx="12" cy="12" r="3"></circle></svg>'
      });
    }

    // 2. Social Trackers Insight
    if (cats.Social > 0) {
      insights.push({
        type: 'soc',
        title: 'Social Tracker Blocking',
        desc: 'Why block Social Trackers? Because platforms like Facebook track your browsing habits even if you aren\'t logged in.',
        icon: '<svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>'
      });
    }

    // 3. Cookies Insight
    if (cats.Cookies > 0) {
      insights.push({
        type: 'cook',
        title: 'Cookie Privacy',
        desc: 'Why block 3rd-party cookies? To prevent advertisers from following you from one site to another.',
        icon: '<svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"></path></svg>'
      });
    }

    if (insights.length > 0) {
      insights.forEach(item => {
        const card = document.createElement('div');
        card.className = 'insight-card';
        card.innerHTML = `
          <div class="insight-icon insight-icon-${item.type}">
            ${item.icon}
          </div>
          <div class="insight-text">
            <span class="insight-title">${item.title}</span>
            <p class="insight-desc">${item.desc}</p>
          </div>
        `;
        insightsContentEl.appendChild(card);
      });
    } else {
      // No trackers detected (Clean Site)
      insightsContentEl.innerHTML = `
        <div class="clean-site-msg">
          <div class="insight-icon insight-icon-clean clean-site-icon">
            <svg viewBox="0 0 24 24" width="32" height="32" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>
          </div>
          <div class="clean-site-text">This site appears clean!</div>
          <p class="insight-desc">No privacy-invasive scripts were found here. Your connection is being monitored but no threats were detected.</p>
        </div>
      `;
    }
  };

  const updateInspectorTable = () => {
    if (!lastStats || !lastStats.blockedRequests) return;
    
    const isManualMode = lastStats.mode === 'manual';
    
    // Show/Hide Manual Control Column Header
    if (manualColHeader) {
      manualColHeader.style.display = isManualMode ? 'table-cell' : 'none';
    }

    inspectorBodyEl.innerHTML = '';
    const filtered = lastStats.blockedRequests.filter(req => 
      req.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
      req.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (req.category && req.category.toLowerCase().includes(searchTerm.toLowerCase()))
    );

    if (filtered.length > 0) {
      // Get current manual blocks for checkbox status
      browser.storage.local.get(['manualBlocks']).then(res => {
        const manualBlocks = res.manualBlocks || [];
        
        // Reverse to show newest at the top
        [...filtered].reverse().forEach((req) => {
          const tr = document.createElement('tr');
          
          // Category Badge logic
          let badgeClass = 'badge-oth';
          const cat = req.category || 'Others';
          if (cat === 'Advertising') badgeClass = 'badge-adv';
          else if (cat === 'Analytics') badgeClass = 'badge-ana';
          else if (cat === 'Social') badgeClass = 'badge-soc';
          else if (cat === 'Cookies') badgeClass = 'badge-cook';
          else if (cat === 'Fingerprinting') badgeClass = 'badge-fin';

          // Status Badge logic
          const isBlocked = req.status === 'Blocked';
          const statusBadgeClass = isBlocked ? 'badge-blocked' : 'badge-allowed';
          const statusText = isBlocked ? 'Blocked' : 'Allowed';

          // Manual Checkbox HTML
          let checkboxHtml = '';
          if (isManualMode) {
            const isChecked = manualBlocks.includes(req.domain);
            checkboxHtml = `<td class="manual-checkbox-cell">
              <input type="checkbox" class="manual-block-checkbox" data-domain="${req.domain}" ${isChecked ? 'checked' : ''}>
            </td>`;
          }

          tr.innerHTML = `
            ${checkboxHtml}
            <td style="font-weight:600; word-break: break-all;">${req.domain}</td>
            <td style="text-transform: capitalize;">${req.type}</td>
            <td><span class="badge-category ${badgeClass}">${cat}</span></td>
            <td><span class="${statusBadgeClass}">${statusText}</span></td>
            <td class="activity-time">${req.timestamp}</td>
          `;
          inspectorBodyEl.appendChild(tr);
        });

        // Add event listeners for manual checkboxes
        if (isManualMode) {
          document.querySelectorAll('.manual-block-checkbox').forEach(cb => {
            cb.addEventListener('change', (e) => {
              const domain = e.target.getAttribute('data-domain');
              browser.runtime.sendMessage({ command: 'toggleManualBlock', domain }).then(() => {
                // Refresh stats and UI after toggle
                fetchStats();
              });
            });
          });
        }
      });
    } else {
      const colSpan = isManualMode ? 6 : 5;
      inspectorBodyEl.innerHTML = `<tr><td colspan="${colSpan}" class="empty-state" style="text-align:center; padding:20px;">No trackers match your search</td></tr>`;
    }
  };

  trackerSearchInput.addEventListener('input', (e) => {
    searchTerm = e.target.value;
    updateInspectorTable();
  });

  const fetchStats = () => {
    browser.tabs.query({ active: true, currentWindow: true }).then(tabs => {
      const activeTab = tabs[0];
      if (activeTab) {
        browser.runtime.sendMessage({ command: 'getStats', tabId: activeTab.id }).then(updateUI);
      }
    });
  };

  // Initial Load
  browser.storage.local.get(['privacyMode', 'blockCookies', 'showNotifications']).then(res => {
    if (res.privacyMode) updateModeUI(res.privacyMode);
    if (res.blockCookies !== undefined) blockCookiesToggle.checked = res.blockCookies;
    if (res.showNotifications !== undefined) showNotificationsToggle.checked = res.showNotifications;
  });

  // Advanced Toggle Listeners
  [blockCookiesToggle, showNotificationsToggle].forEach(toggle => {
    toggle.addEventListener('change', (e) => {
      const id = e.target.id;
      const checked = e.target.checked;
      browser.storage.local.set({ [id]: checked });
      // Sync with background's protectionSettings
      browser.runtime.sendMessage({ command: 'updateSettings', settings: { [id]: checked } });
      console.log(`${id} set to ${checked}`);
    });
  });

  // Protection Overview Toggle Listeners
  const updateProtectionSettings = () => {
    const settings = {
      adBlocking: toggleAdBlocking.checked,
      socialTrackers: toggleSocialTrackers.checked,
      fingerprinting: toggleFingerprinting.checked
    };
    browser.runtime.sendMessage({ command: 'updateSettings', settings });
  };

  [toggleAdBlocking, toggleSocialTrackers, toggleFingerprinting].forEach(toggle => {
    toggle.addEventListener('change', updateProtectionSettings);
  });
  
  fetchStats();
  setInterval(fetchStats, 2000);
});
