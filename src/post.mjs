import { post } from "./lib.mjs";

// The token expires on its own within an hour, so a failed revoke only warns.
post({ env: process.env }).catch((err) => {
  process.stdout.write(`::warning::Could not revoke the installation token: ${err.message}\n`);
});
