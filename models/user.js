const Datastore = require("nedb-promises");

const User = Datastore.create({
  filename: "users.db",
  autoload: true,
});

const UserRefreshTokens = Datastore.create("userrefreshtoken.db");

module.exports = {
  User,
  UserRefreshTokens,
};
