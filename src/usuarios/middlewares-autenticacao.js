const passport = require('passport');

module.exports = {
    local: (req, res, next) => {
        passport.authenticate(
            'local', { session: false },
            (erro, usuario, info) => {
                if (erro && erro.name === 'InvalidArgumentErro') {
                    return res.status(401).json({ erro: erro.message });
                }
                if (erro) {
                    return res.status(500).json({ erro: erro.message });
                }
                if (!usuario) {
                    return res.status(401).json({});
                }

                req.user = usuario;
                return next();
            }
        )(req, res, next);
    },
    bearer: function(req, res, next) {
        passport.authenticate(
            'bearer', { session: false },
            (erro, usuario, info) => {
                if (erro && erro.name === 'JsonWebTokenErro') {
                    return res.status(401).json({ erro: erro.message });
                }
                if (erro && erro.name === 'TokenExpiredError') {
                    return res
                        .status(401)
                        .json({ erro: erro.message, expiradoEm: erro.expiredAt });
                }
                if (erro) {
                    return res.status(500).json({ erro: erro.message });
                }

                if (!usuario) {
                    return res.status(401).json({});
                }
                req.token = info.token;
                req.user = usuario;
                return next();
            }
        )(req, res, next);
    },
};