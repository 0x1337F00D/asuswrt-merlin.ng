#include <assert.h>

struct wanduck_transition_input {
	int observed_state;
	int previous_state;
	int changed_state;
	int disconnect_count;
	int maximum_disconnect_count;
	int data_limit_reached;
	int disconnect_case;
	int wan_disabled;
	int ppp_auth_failed;
	int other_configured;
	int other_link_up;
	int other_data_limited;
	int special_states_enabled;
};

struct wanduck_transition_output {
	int previous_state;
	int changed_state;
	int disconnect_count;
};

extern int rust_wanduck_transition(const struct wanduck_transition_input *,
    struct wanduck_transition_output *);

int main(void)
{
	struct wanduck_transition_input input = {
		.observed_state = 1,
		.previous_state = 0,
		.changed_state = 99,
		.disconnect_count = -1,
		.maximum_disconnect_count = 12,
		.other_configured = 1,
		.other_link_up = 1,
		.special_states_enabled = 1,
	};
	struct wanduck_transition_output output = {99, 99, 99};

	assert(rust_wanduck_transition(&input, &output) == 1);
	assert(output.previous_state == 1);
	assert(output.changed_state == 4);
	assert(output.disconnect_count == -1);
	input.observed_state = 1234;
	assert(rust_wanduck_transition(&input, &output) == 0);
	return 0;
}
