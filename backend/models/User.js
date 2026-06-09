/**
 * User Model
 * 
 * In-memory user storage with OAuth account linking support.
 * In production, replace with a real database (MongoDB, PostgreSQL, etc.)
 */

class User {
  constructor(data = {}) {
    this.id = data.id || User.generateId();
    this.email = data.email || null;
    this.password = data.password || null; // bcrypt hashed
    this.name = data.name || data.displayName || null;
    this.avatar = data.avatar || data.picture || null;
    this.createdAt = data.createdAt || new Date();
    this.lastLogin = data.lastLogin || null;
    
    // OAuth accounts linked to this user
    this.accounts = data.accounts || [];
  }

  static generateId() {
    return 'user_' + Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
  }

  /**
   * Find user by ID
   */
  static findById(id) {
    return User.store[id] || null;
  }

  /**
   * Find user by email (local account)
   */
  static findByEmail(email) {
    if (!email) return null;
    const lowerEmail = email.toLowerCase();
    return Object.values(User.store).find(u => 
      u.email && u.email.toLowerCase() === lowerEmail && u.password
    ) || null;
  }

  /**
   * Find user by OAuth provider
   */
  static findByProvider(provider, providerId) {
    return Object.values(User.store).find(u => 
      u.accounts.some(acc => acc.provider === provider && acc.providerId === providerId)
    ) || null;
  }

  /**
   * Create a new local user
   */
  static create(data) {
    const user = new User(data);
    User.store[user.id] = user;
    return user;
  }

  /**
   * Link an OAuth account to existing user
   */
  addAccount(provider, providerId, profile) {
    const exists = this.accounts.some(acc => 
      acc.provider === provider && acc.providerId === providerId
    );
    if (!exists) {
      this.accounts.push({
        provider,
        providerId,
        email: profile.email,
        displayName: profile.displayName || profile.name,
        avatar: profile.picture || profile.avatarUrl,
        linkedAt: new Date()
      });
    }
    this.lastLogin = new Date();
    User.store[this.id] = this;
    return this;
  }

  /**
   * Get public user info (no sensitive data)
   */
  toPublicJSON() {
    return {
      id: this.id,
      email: this.email,
      name: this.name,
      avatar: this.avatar,
      accounts: this.accounts.map(acc => ({
        provider: acc.provider,
        displayName: acc.displayName,
        avatar: acc.avatar
      })),
      createdAt: this.createdAt,
      lastLogin: this.lastLogin
    };
  }

  toJSON() {
    return this.toPublicJSON();
  }
}

// In-memory store (replace with database in production)
User.store = {};

module.exports = User;