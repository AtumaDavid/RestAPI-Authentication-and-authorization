const { Router } = require("express");
const {
  register,
  stay,
  login,
  loggedin,
} = require("../controllers/controller");
const ensureAuthenticated = require("../middleware/ensureAuthenticated");

const router = Router();

router.get("/", stay);
router.post("/api/auth/register", register);
router.post("/api/auth/login", login);
// The middleware ensureAuthenticated is responsible for verifying that a user is authenticated before allowing them access to certain routes.
router.get("/api/users/loggedin", ensureAuthenticated, loggedin);

module.exports = router;
