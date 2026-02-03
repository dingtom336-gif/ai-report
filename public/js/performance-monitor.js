/**
 * Performance Monitor for AI Report
 * Tracks page load times, resource loading, and API call performance
 */

(function() {
  'use strict';

  const PerformanceMonitor = {
    // Store metrics
    metrics: {
      pageLoad: null,
      resources: [],
      apiCalls: []
    },

    // Initialize monitoring
    init() {
      this.measurePageLoad();
      this.measureResources();
      this.interceptFetch();
      console.log('[PerfMonitor] Initialized');
    },

    // Measure page load performance
    measurePageLoad() {
      if (window.performance && window.performance.timing) {
        window.addEventListener('load', () => {
          // Use setTimeout to ensure all timing data is available
          setTimeout(() => {
            const timing = performance.timing;
            const metrics = {
              // DNS lookup time
              dns: timing.domainLookupEnd - timing.domainLookupStart,
              // TCP connection time
              tcp: timing.connectEnd - timing.connectStart,
              // Time to First Byte (TTFB)
              ttfb: timing.responseStart - timing.requestStart,
              // DOM parsing time
              domParse: timing.domContentLoadedEventEnd - timing.domLoading,
              // Page fully loaded
              loadComplete: timing.loadEventEnd - timing.navigationStart,
              // DOM interactive
              domInteractive: timing.domInteractive - timing.navigationStart
            };

            this.metrics.pageLoad = metrics;
            this.logMetrics('Page Load', metrics);

            // Report to console with formatted table
            console.log('[PerfMonitor] Page Load Metrics:');
            console.table({
              'DNS查询': `${metrics.dns}ms`,
              'TCP连接': `${metrics.tcp}ms`,
              '首字节(TTFB)': `${metrics.ttfb}ms`,
              'DOM解析': `${metrics.domParse}ms`,
              'DOM可交互': `${metrics.domInteractive}ms`,
              '完全加载': `${metrics.loadComplete}ms`
            });

            // Warn if page load is slow
            if (metrics.loadComplete > 3000) {
              console.warn(`[PerfMonitor] Page load slow: ${metrics.loadComplete}ms (target: <3000ms)`);
            }
          }, 100);
        });
      }
    },

    // Measure resource loading times
    measureResources() {
      window.addEventListener('load', () => {
        setTimeout(() => {
          const resources = performance.getEntriesByType('resource');
          const slowResources = [];

          resources.forEach(r => {
            const duration = Math.round(r.duration);
            const entry = {
              name: r.name.split('/').pop() || r.name,
              fullUrl: r.name,
              type: r.initiatorType,
              duration: duration,
              size: r.transferSize || 0
            };

            this.metrics.resources.push(entry);

            // Track slow resources (>1000ms)
            if (duration > 1000) {
              slowResources.push(entry);
            }
          });

          if (slowResources.length > 0) {
            console.warn('[PerfMonitor] Slow resources detected:');
            console.table(slowResources.map(r => ({
              '资源': r.name,
              '类型': r.type,
              '耗时': `${r.duration}ms`,
              '大小': r.size ? `${Math.round(r.size/1024)}KB` : 'N/A'
            })));
          }

          // Check for failed external resources
          const externalResources = resources.filter(r =>
            r.name.includes('cdn.') ||
            r.name.includes('cdnjs.') ||
            r.name.includes('jsdelivr.')
          );

          if (externalResources.length > 0) {
            console.log('[PerfMonitor] External CDN resources:', externalResources.map(r => ({
              url: r.name,
              duration: `${Math.round(r.duration)}ms`
            })));
          }
        }, 100);
      });
    },

    // Intercept fetch calls to measure API performance
    interceptFetch() {
      const originalFetch = window.fetch;
      const self = this;

      window.fetch = async function(...args) {
        const url = args[0];
        const isApiCall = typeof url === 'string' && url.includes('/api/');

        if (!isApiCall) {
          return originalFetch.apply(this, args);
        }

        const startTime = Date.now();
        let firstChunkTime = null;
        const endpoint = url.split('?')[0];

        try {
          const response = await originalFetch.apply(this, args);

          // Clone response to read it without consuming
          const clonedResponse = response.clone();

          // Track first chunk time for streaming responses
          if (response.headers.get('content-type')?.includes('text/event-stream')) {
            const reader = clonedResponse.body?.getReader();
            if (reader) {
              reader.read().then(() => {
                firstChunkTime = Date.now() - startTime;
                console.log(`[PerfMonitor] ${endpoint} first chunk: ${firstChunkTime}ms`);
              }).catch(() => {});
            }
          }

          // Log API call completion
          const duration = Date.now() - startTime;
          const metric = {
            endpoint,
            duration,
            firstChunkTime,
            status: response.status,
            success: response.ok,
            timestamp: new Date().toISOString()
          };

          self.metrics.apiCalls.push(metric);
          self.logApiCall(metric);

          return response;
        } catch (error) {
          const duration = Date.now() - startTime;
          const metric = {
            endpoint,
            duration,
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
          };

          self.metrics.apiCalls.push(metric);
          self.logApiCall(metric);

          throw error;
        }
      };
    },

    // Log API call metrics
    logApiCall(metric) {
      const status = metric.success ? '✓' : '✗';
      const color = metric.success ? 'color: green' : 'color: red';

      console.log(
        `%c[PerfMonitor] API ${status} ${metric.endpoint}: ${metric.duration}ms`,
        color
      );

      // Warn if API call is slow
      if (metric.duration > 5000) {
        console.warn(`[PerfMonitor] Slow API call: ${metric.endpoint} took ${metric.duration}ms`);
      }
    },

    // Generic metrics logging
    logMetrics(category, data) {
      if (typeof data === 'object') {
        const formatted = {};
        for (const [key, value] of Object.entries(data)) {
          formatted[key] = typeof value === 'number' ? `${value}ms` : value;
        }
        console.log(`[PerfMonitor] ${category}:`, formatted);
      }
    },

    // Get summary of all metrics
    getSummary() {
      const apiCalls = this.metrics.apiCalls;
      const successfulCalls = apiCalls.filter(c => c.success);
      const avgDuration = successfulCalls.length > 0
        ? Math.round(successfulCalls.reduce((sum, c) => sum + c.duration, 0) / successfulCalls.length)
        : 0;

      return {
        pageLoad: this.metrics.pageLoad,
        resourceCount: this.metrics.resources.length,
        slowResources: this.metrics.resources.filter(r => r.duration > 1000).length,
        apiCalls: {
          total: apiCalls.length,
          successful: successfulCalls.length,
          failed: apiCalls.length - successfulCalls.length,
          avgDuration: avgDuration
        }
      };
    },

    // Print summary to console
    printSummary() {
      const summary = this.getSummary();
      console.log('[PerfMonitor] === Performance Summary ===');
      console.table({
        '页面加载': summary.pageLoad ? `${summary.pageLoad.loadComplete}ms` : 'N/A',
        '资源总数': summary.resourceCount,
        '慢资源数': summary.slowResources,
        'API调用数': summary.apiCalls.total,
        'API成功数': summary.apiCalls.successful,
        'API平均耗时': `${summary.apiCalls.avgDuration}ms`
      });
    }
  };

  // Initialize on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => PerformanceMonitor.init());
  } else {
    PerformanceMonitor.init();
  }

  // Expose to global scope for debugging
  window.PerfMonitor = PerformanceMonitor;

  // Print summary after page fully loads
  window.addEventListener('load', () => {
    setTimeout(() => PerformanceMonitor.printSummary(), 2000);
  });
})();
