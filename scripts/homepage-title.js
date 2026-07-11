/* global hexo */

const { escapeHTML } = require('hexo-util');

// The custom landing page is rendered through NexT's generic page layout.
// Because it intentionally has no page title, NexT emits " | Site Name".
// Correct only the canonical homepage at build time so every client receives
// the final title in the static HTML without relying on JavaScript.
hexo.extend.filter.register('after_render:html', function(html) {
  const siteUrl = this.config.url.replace(/\/+$/, '');
  const root = this.config.root || '/';
  const homepageUrl = `${siteUrl}${root}`;
  const canonicalTag = `<link rel="canonical" href="${homepageUrl}">`;

  if (!html.includes(canonicalTag)) return html;

  const title = escapeHTML(this.config.title);
  return html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${title}</title>`);
});
