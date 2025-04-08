const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.static('public'));
app.use(express.json());

// Simulación de base de datos en memoria (en producción, usar una base de datos real)
let users;
let reminders = [];

async function hashPassword(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
            if (err) reject(err);
            resolve(salt + ':' + derivedKey.toString('hex'));
        });
    });
}

async function verifyPassword(password, storedHash) {
    const [salt, key] = storedHash.split(':');
    return new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
            if (err) reject(err);
            resolve(storedHash === salt + ':' + derivedKey.toString('hex'));
        });
    });
}

function generateToken() {
    return crypto.randomBytes(48).toString('hex');
}

function validateReminder(content, important) {
    if (typeof content !== 'string' || content.trim().length === 0 || content.length > 120) {
        return false;
    }
    if (important !== undefined && typeof important !== 'boolean') {
        return false;
    }
    return true;
}

(async () => {
    // Inicialización de usuarios con contraseña hasheada
    users = [{ username: 'admin', password: await hashPassword('password123', 'salt'), token: generateToken() }];

    // Resto del código...
    const authenticate = (req, res, next) => {
        const token = req.headers['x-authorization'];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }
        const user = users.find(u => u.token === token);
        if (!user) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        next();
    };

    app.post('/api/auth/login', async (req, res) => {
        const { username, password } = req.body;
        const user = users.find(u => u.username === username);
        if (!user) return res.status(401).json({ error: 'User not found' });

        if (await verifyPassword(password, user.password)) {
            user.token = generateToken();
            return res.status(200).json({ username: user.username, name: 'Admin', token: user.token });
        } else {
            return res.status(401).json({ error: 'Invalid password' });
        }
    });

    app.get('/api/reminders', authenticate, (req, res) => {
        const orderedReminders = reminders.sort((a, b) => b.createdAt - a.createdAt);
        res.status(200).json(orderedReminders.map(reminder => ({
            id: reminder.id,
            content: reminder.content,
            important: reminder.important,
            createdAt: reminder.createdAt,
        })));
    });

    app.post('/api/reminders', authenticate, (req, res) => {
        const { content, important } = req.body;
        if (!validateReminder(content, important)) {
            return res.status(400).json({ error: 'Invalid content or important' });
        }

        const newReminder = {
            id: crypto.randomBytes(16).toString('hex'),
            content: content,
            important: important || false,
            createdAt: Date.now(),
        };

        reminders.push(newReminder);
        res.status(201).json(newReminder);
    });

    app.patch('/api/reminders/:id', authenticate, (req, res) => {
        const { id } = req.params;
        const { content, important } = req.body;
        const reminder = reminders.find(r => r.id === id);

        if (!reminder) return res.status(404).json({ error: 'Reminder not found' });

        if (content !== undefined && !validateReminder(content, important)) {
            return res.status(400).json({ error: 'Invalid content or important' });
        }

        reminder.content = content || reminder.content;
        reminder.important = important !== undefined ? important : reminder.important;

        res.status(200).json({
            id: reminder.id,
            content: reminder.content,
            important: reminder.important,
            createdAt: reminder.createdAt,
        });
    });

    app.delete('/api/reminders/:id', authenticate, (req, res) => {
        const { id } = req.params;
        const index = reminders.findIndex(r => r.id === id);

        if (index === -1) return res.status(404).json({ error: 'Reminder not found' });

        reminders.splice(index, 1);
        res.status(204).send();
    });

    app.post('/api/auth/logout', authenticate, (req, res) => {
      const token = req.headers['x-authorization'];
      const userIndex = users.findIndex(user => user.token === token);

      if (userIndex !== -1) {
        users[userIndex].token = null;
        res.status(200).json({ message: 'Logout successful' });
      } else {
        res.status(401).json({ error: 'Invalid token' });
      }
    });

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Servidor corriendo en http://localhost:${PORT}`);
    });
})();