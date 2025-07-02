const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
  // Pega o header Authorization, que deve ter o token no formato "Bearer <token>"
  const authHeader = req.headers['authorization'];
  
  // Se não tem header Authorization, retorna erro 401 (não autorizado)
  if (!authHeader) return res.status(401).json({ error: 'Token não fornecido' });

  // Separa o "Bearer" do token
  const token = authHeader.split(' ')[1];
  
  // Se não tem token depois do "Bearer", retorna erro 401 (mal formatado)
  if (!token) return res.status(401).json({ error: 'Token mal formatado' });

  // Verifica o token com a chave secreta
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });

    // Se tudo certo, coloca o userId e email decodificados no objeto req
    req.userId = decoded.userId;
    req.email = decoded.email;

    // Passa pra próxima função (a rota protegida)
    next();
  });
}

module.exports = verifyToken;
