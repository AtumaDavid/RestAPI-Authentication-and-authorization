const Datastore = require("nedb-promises");

const User = Datastore.create({
  filename: "users.db",
  autoload: true,
});

module.exports = User;
