const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function (app) {
  app.use(
    '/authority',
    createProxyMiddleware({
      target: 'http://localhost:3030',
      changeOrigin: true,
      pathRewrite: { '^/authority': '' }
    })
  );
  app.use(
    '/owner',
    createProxyMiddleware({
      target: 'http://localhost:3035',
      changeOrigin: true,
      pathRewrite: { '^/owner': '' }
    })
  );
  app.use(
    '/purchaser',
    createProxyMiddleware({
      target: 'http://localhost:3032',
      changeOrigin: true,
      pathRewrite: { '^/purchaser': '' }
    })
  );
};
