require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const verifyToken = require('./middleware/verifytoken');

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

app.post('/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha são obrigatórios.' });

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ error: 'Email já cadastrado.' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await prisma.user.create({
      data: { email, password: hashedPassword, name },
    });

    res.status(201).json({
      message: 'Usuário criado com sucesso.',
      user: { id: newUser.id, email: newUser.email, name: newUser.name },
    });
  } catch {
    res.status(500).json({ error: 'Erro no servidor.' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha são obrigatórios.' });

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: 'Credenciais inválidas.' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ error: 'Credenciais inválidas.' });

    const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: 'Login realizado com sucesso.', token });
  } catch {
    res.status(500).json({ error: 'Erro no servidor.' });
  }
});

app.get('/users/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  if (parseInt(id) !== req.userId) return res.status(403).json({ error: 'Acesso negado' });

  try {
    const user = await prisma.user.findUnique({
      where: { id: parseInt(id) },
      select: { id: true, email: true, name: true, createdAt: true },
    });
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

    res.json(user);
  } catch {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.put('/users/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { name, email, password } = req.body;

  if (parseInt(id) !== req.userId) {
    return res.status(403).json({ error: 'Acesso negado' });
  }

  const updateData = {};
  if (name) updateData.name = name;
  if (email) updateData.email = email;
  if (password) updateData.password = await bcrypt.hash(password, 10);

  try {
    const updatedUser = await prisma.user.update({
      where: { id: parseInt(id) },
      data: updateData,
      select: { id: true, email: true, name: true, createdAt: true },
    });

    res.json({
      message: 'Usuário atualizado com sucesso.',
      user: updatedUser,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar usuário.' });
  }
});

app.delete('/users/:id', verifyToken, async (req, res) => {
  const { id } = req.params;

  if (parseInt(id) !== req.userId) {
    return res.status(403).json({ error: 'Acesso negado' });
  }

  try {
    await prisma.user.delete({
      where: { id: parseInt(id) }
    });

    res.json({ message: 'Conta deletada com sucesso.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao deletar usuário.' });
  }
});



const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
