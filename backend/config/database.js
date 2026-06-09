const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

// In-memory store
let users = [];
const usersFilePath = path.join(__dirname, '../data/users.json');

// Ensure data directory exists
const dataDir = path.dirname(usersFilePath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Load users from file if exists
function loadUsers() {
  try {
    if (fs.existsSync(usersFilePath)) {
      const data = fs.readFileSync(usersFilePath, 'utf8');
      users = JSON.parse(data);
    }
  } catch (err) {
    console.error('Error loading users:', err);
    users = [];
  }
}

// Save users to file
function saveUsers() {
  try {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
  } catch (err) {
    console.error('Error saving users:', err);
  }
}

// Initialize database
function initDatabase() {
  loadUsers();
  console.log(`Database initialized with ${users.length} users`);
}

// User schema: { id, provider, providerId, email, name, avatar, createdAt }

// Find user by various criteria
async function findUser(query) {
  if (query.id) {
    return users.find(u => u.id === query.id);
  }
  if (query.provider && query.providerId) {
    return users.find(u => 
      u.provider === query.provider && 
      u.providerId === query.providerId
    );
  }
  if (query.email) {
    return users.find(u => u.email === query.email);
  }
  return null;
}

// Find or create user (used by passport strategies)
async function findOrCreateUser(userData) {
  let user = await findUser({
    provider: userData.provider,
    providerId: userData.providerId
  });

  if (!user) {
    // Check if email already exists
    user = await findUser({ email: userData.email });
    
    if (!user) {
      // Create new user
      user = {
        id: uuidv4(),
        provider: userData.provider,
        providerId: userData.providerId,
        email: userData.email,
        name: userData.name,
        avatar: userData.avatar,
        createdAt: new Date().toISOString()
      };
      users.push(user);
      saveUsers();
      console.log(`New user created: ${user.email}`);
    } else {
      // Link provider to existing user
      user.provider = userData.provider;
      user.providerId = userData.providerId;
      if (!user.avatar && userData.avatar) {
        user.avatar = userData.avatar;
      }
      saveUsers();
      console.log(`Existing user linked: ${user.email}`);
    }
  }

  return user;
}

// Create user (explicit)
async function createUser(userData) {
  const existingUser = await findUser({ email: userData.email });
  if (existingUser) {
    throw new Error('User already exists');
  }

  const user = {
    id: uuidv4(),
    provider: userData.provider || 'local',
    providerId: userData.providerId || '',
    email: userData.email,
    name: userData.name || '',
    avatar: userData.avatar || '',
    createdAt: new Date().toISOString()
  };

  users.push(user);
  saveUsers();
  return user;
}

// Update user
async function updateUser(id, updates) {
  const index = users.findIndex(u => u.id === id);
  if (index === -1) {
    throw new Error('User not found');
  }

  users[index] = { ...users[index], ...updates };
  saveUsers();
  return users[index];
}

// Find by email
async function findByEmail(email) {
  return users.find(u => u.email === email) || null;
}

// Get all users (admin function)
async function getAllUsers() {
  return users.map(u => ({ ...u }));
}

module.exports = {
  initDatabase,
  findUser,
  findOrCreateUser,
  createUser,
  updateUser,
  findByEmail,
  getAllUsers
};