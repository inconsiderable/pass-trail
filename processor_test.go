package passtrail

import "testing"

func TestComputeMaxConsiderationsPerPass(t *testing.T) {
	var maxDoublings int64 = 64
	var doublings int64
	previous := INITIAL_MAX_CONSIDERATIONS_PER_PASS / 2
	// verify the max is always doubling as expected
	for doublings = 0; doublings < maxDoublings; doublings++ {
		var height int64 = doublings * PASSES_UNTIL_CONSIDERATIONS_PER_PASS_DOUBLING
		max := computeMaxConsiderationsPerPass(height)
		if max < INITIAL_MAX_CONSIDERATIONS_PER_PASS {
			t.Fatalf("Max %d at height %d less than initial", max, height)
		}
		expect := previous * 2
		if expect > MAX_CONSIDERATIONS_PER_PASS {
			expect = MAX_CONSIDERATIONS_PER_PASS
		}
		if max != expect {
			t.Fatalf("Max %d at height %d not equal to expected max %d",
				max, height, expect)
		}
		if doublings > 0 {
			var previous2 int = max
			// walk back over the previous period and make sure:
			// 1) the max is never greater than this period's first max
			// 2) the max is always <= the previous as we walk back
			for height -= 1; height >= (doublings-1)*PASSES_UNTIL_CONSIDERATIONS_PER_PASS_DOUBLING; height-- {
				max2 := computeMaxConsiderationsPerPass(height)
				if max2 > max {
					t.Fatalf("Max %d at height %d is greater than next period's first max %d",
						max2, height, max)
				}
				if max2 > previous2 {
					t.Fatalf("Max %d at height %d is greater than previous max %d at height %d",
						max2, height, previous2, height+1)
				}
				previous2 = max2
			}
		}
		previous = max
	}
	max := computeMaxConsiderationsPerPass(MAX_CONSIDERATIONS_PER_PASS_EXCEEDED_AT_HEIGHT)
	if max != MAX_CONSIDERATIONS_PER_PASS {
		t.Fatalf("Expected %d at height %d, found %d",
			MAX_CONSIDERATIONS_PER_PASS, MAX_CONSIDERATIONS_PER_PASS_EXCEEDED_AT_HEIGHT, max)
	}
	max = computeMaxConsiderationsPerPass(MAX_CONSIDERATIONS_PER_PASS_EXCEEDED_AT_HEIGHT + 1)
	if max != MAX_CONSIDERATIONS_PER_PASS {
		t.Fatalf("Expected %d at height %d, found",
			MAX_CONSIDERATIONS_PER_PASS, MAX_CONSIDERATIONS_PER_PASS_EXCEEDED_AT_HEIGHT+1)
	}
	max = computeMaxConsiderationsPerPass(MAX_CONSIDERATIONS_PER_PASS_EXCEEDED_AT_HEIGHT - 1)
	if max >= MAX_CONSIDERATIONS_PER_PASS {
		t.Fatalf("Expected less than max at height %d, found %d",
			MAX_CONSIDERATIONS_PER_PASS_EXCEEDED_AT_HEIGHT-1, max)
	}
}
