-- Ends every PIN reset left pending by the retired unauthenticated reset endpoints.
--
-- The delayed account recovery reuses pin_reset_requested_at as its episode stamp. A stamp written by
-- the retired POST /security/pin/reset was opened before any code was checked and while no signed-in
-- app could show a recovery banner, so read under the new rules it could already be READY on the day
-- this ships and be completed without the account holder ever having had the wait with a visible
-- cancel. No episode from the old flow survives: a user who still needs one starts a recovery at
-- sign-in and gets the full wait.
--
-- Data only, so the schema mirror is unchanged.
-- A stamp an old instance writes during a rolling deploy, after this runs, starts its wait while the
-- new instances already publish the banner, so it gets the full wait with the cancel visible.
UPDATE identity_users
SET pin_reset_requested_at = NULL
WHERE pin_reset_requested_at IS NOT NULL;
