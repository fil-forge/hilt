package testutil

import "time"

// WaitTimeout is how long a call that must finish is given before the test fails.
const WaitTimeout = 10 * time.Second
