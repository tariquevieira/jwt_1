const usuariosControlador = require('./usuarios-controlador');
const passport = require('passport');
const middlewareAutenticacao = require('./middlewares-autenticacao');

module.exports = (app) => {
    app
        .route('/usuario/login')
        .post(middlewareAutenticacao.local, usuariosControlador.login);
    app
        .route('/usuario/logout')
        .get(middlewareAutenticacao.bearer, usuariosControlador.logout);
    app
        .route('/usuario')
        .post(middlewareAutenticacao.bearer, usuariosControlador.adiciona)
        .get(usuariosControlador.lista);

    app.route('/usuario/:id').delete(usuariosControlador.deleta);
};