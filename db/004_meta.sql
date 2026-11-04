-- Meta connections: Meta has no refresh token, so a connection records when its long-lived token
-- (about 60 days) expires. The app warns ahead of time and marks it "needs reconnect" once it lapses.
ALTER TABLE connections ADD COLUMN token_expires_at timestamptz;
GRANT SELECT (token_expires_at) ON connections TO ordix_member;
