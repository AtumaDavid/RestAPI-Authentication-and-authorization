const { Router } = require("express");
const {
  register,
  stay,
  login,
  loggedin,
  admin,
  moderators,
  refreshtoken,
} = require("../controllers/controller");
const ensureAuthenticated = require("../middleware/ensureAuthenticated");
const authorize = require("../middleware/authorize");

const router = Router();

router.get("/", stay);
router.post("/api/auth/register", register);
router.post("/api/auth/login", login);
// refresh token
router.post("/api/auth/refresh-token", refreshtoken);
// The middleware ensureAuthenticated is responsible for verifying that a user is authenticated before allowing them access to certain routes.
router.get("/api/users/loggedin", ensureAuthenticated, loggedin);
router.get("/api/admin", ensureAuthenticated, authorize(["admin"]), admin);
router.get(
  "/api/moderator",
  ensureAuthenticated,
  authorize(["admin", "moderator"]),
  moderators
);

module.exports = router;
