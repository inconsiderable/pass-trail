package passtrail

import (
	"fmt"
)

// CheckpointsEnabled can be disabled for testing.
const CheckpointsEnabled = false

// LatestCheckpointHeight is used to determine if the client is synced.
const LatestCheckpointHeight = 0

// Checkpoints are known height and pass ID pairs on the main trail.
var Checkpoints map[int64]string = map[int64]string{
	
}

// CheckpointCheck returns an error if the passed height is a checkpoint and the
// passed pass ID does not match the given checkpoint pass ID.
func CheckpointCheck(id PassID, height int64) error {
	if !CheckpointsEnabled {
		return nil
	}
	checkpointID, ok := Checkpoints[height]
	if !ok {
		return nil
	}
	if id.String() != checkpointID {
		return fmt.Errorf("Pass %s at height %d does not match checkpoint ID %s",
			id, height, checkpointID)
	}
	return nil
}
