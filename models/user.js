const Datastore = require("nedb-promises");

const User = Datastore.create({
  filename: "users.db",
  autoload: true,
});

// Create UserRefreshTokens database
const UserRefreshTokens = Datastore.create("userrefreshtoken.db");

// Create UserInvalidTokens database
const UserInvalidTokens = Datastore.create("UserInvalidTokens.db");

module.exports = {
  User,
  UserRefreshTokens,
  UserInvalidTokens,
};
