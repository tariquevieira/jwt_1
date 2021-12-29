const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const Usuario = require('./usuarios-modelo');
const { InvalidArgumentError } = require('../erros');
const bcrypt = require('bcrypt');
const BearerStrategy = require('passport-http-bearer').Strategy;
const jwt = require('jsonwebtoken');
const blacklist = require('../../redis/manipula-blacklist');

function verificaUsuario(usuario) {
    if (!usuario) throw new InvalidArgumentError('Email ou senha invalidos');
}

async function verificaTokenNaBlackList(token) {
    const tokenNaBlackList = await blacklist.contemToken(token);
    if (tokenNaBlackList) {
        throw new jwt.JsonWebTokenError('Token inválido por logout');
    }
}

async function verificaSenha(senha, senhaHash) {
    const senhaValida = await bcrypt.compare(senha, senhaHash);
    if (!senhaValida) throw new InvalidArgumentError('Email ou senha invalidos');
}

passport.use(
    new LocalStrategy({
            usernameField: 'email',
            passwordField: 'senha',
            session: false,
        },
        async(email, senha, done) => {
            try {
                const usuario = await Usuario.buscaPorEmail(email);
                verificaUsuario(usuario);
                await verificaSenha(senha, usuario.senhaHash);
                done(null, usuario);
            } catch (error) {
                done(error);
            }
        }
    )
);

passport.use(
    new BearerStrategy(async(token, done) => {
        try {
            await verificaTokenNaBlackList(token);
            const payload = jwt.verify(token, process.env.CHAVE_JWT);
            const usuario = await Usuario.buscaPorId(payload.id);
            done(null, usuario, { token: token });
        } catch (error) {
            done(error);
        }
    })
);