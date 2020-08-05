#ifndef _PH_LINK_H_
#define _PH_LINK_H_

// return codes during sending of message
#define PH_LINK_TX_OK							0
#define PH_LINK_TX_OK_SEQUENCE_OVERFLOWN		1
#define _PH_LINK_TX_MIN_ERROR_VALUE				100
#define PH_LINK_TX_CALLBACK_UNDEFINED			_PH_LINK_TX_MIN_ERROR_VALUE + 1
#define PH_LINK_TX_NO_MEMORY					_PH_LINK_TX_MIN_ERROR_VALUE + 2

// return codes during reception&decoding of message from the stream
#define PH_LINK_RX_OK							0
#define PH_LINK_RX_OK_RESYNC_SKIP_WIN			1 // re-synced within PH_LINK_SEQUENCE_RX_SKIP_WINDOW
#define PH_LINK_RX_OK_RESYNC_BIG_WIN			2 // re-synced by PH_LINK_SEQUENCE_RX_RESYNC_WINDOW
#define _PH_LINK_RX_MIN_ERROR_VALUE				100
#define PH_LINK_RX_NO_MEMORY					_PH_LINK_RX_MIN_ERROR_VALUE + 1
#define PH_LINK_RX_SEQUENCE_ERR					_PH_LINK_RX_MIN_ERROR_VALUE + 2
#define PH_LINK_RX_CMAC_INVALID					_PH_LINK_RX_MIN_ERROR_VALUE + 3
#define PH_LINK_RX_SEQUENCE_BIGWIN_ACTIVE		_PH_LINK_RX_MIN_ERROR_VALUE + 4

// length of certain fields of the payload in ctx.buffer
#define PH_LINK_RANDOM_IV_SIZE					8 // dynamic, you can change this. ideal = 16
#define PH_LINK_SEQUENCE_SIZE					4 // fixed to 4 bytes
#define PH_LINK_PADDING_LENGTH_SIZE				1 // fixed to 1 byte
#define PH_LINK_CMAC_SIZE						16 // fixed to 16 bytes

#define PH_LINK_MAX_SEQUENCE_VALUE				((uint32_t)0xFFFFFFFF) // corresponds to the maximum value of the length of PH_LINK_SEQUENCE_SIZE which is 4 bytes fixed

// link configuration
#define PH_LINK_SEQUENCE_RX_RESYNC_SKIP_WINDOW			50 // if we skipped some messages in reception, this is the window to accept it even though we skipped some!
#define PH_LINK_SEQUENCE_RX_RESYNC_BIG_WINDOW			1000 // how many messages are we allowed to skip in reception in order to accept the next ones and re-sync our internal rx_sequence counter. NOTE: MUST NOT BE GREATER THAN (1/2(2^PH_LINK_SEQUENCE_SIZE))
#define PH_LINK_SEQUENCE_RX_RESYNC_BIG_WINDOW_COUNTER	5 // how many successive messages must we receive in order to re-sync within the PH_LINK_SEQUENCE_RX_RESYNC_WINDOW window

struct PH_LINK_message {
	uint32_t length;
	uint8_t* data;
};

struct PH_LINK_ctx {
	uint32_t tx_sequence;
	uint32_t rx_sequence;

	uint8_t rx_sequence_big_window_active;
	uint32_t rx_sequence_big_window_value;
	uint32_t rx_sequence_big_window_counter;

	uint8_t* buffer;
	uint32_t buffer_size;

	void (*aes_cipher_callback)(uint8_t* data, uint32_t length);
	void (*aes_decipher_callback)(uint8_t* data, uint32_t length);
	void (*cmac_generate_callback)(uint8_t* data, uint32_t length, uint8_t* result);
	void (*random_callback)(uint8_t* data, uint8_t length);
	void (*on_receive_callback)(uint8_t rx_status, struct PH_LINK_message* msg);
	void (*on_send_callback)(uint8_t* data, uint32_t length);
};

void PH_LINK_init_sequences_ctx(struct PH_LINK_ctx* ctx, uint32_t tx_sequence, uint32_t rx_sequence);
void PH_LINK_init_buffer_ctx(struct PH_LINK_ctx* ctx, uint8_t* buffer, uint32_t buffer_size);
void PH_LINK_init_callbacks_ctx(struct PH_LINK_ctx* ctx, void(*aes_cipher_callback)(uint8_t*, uint32_t), void(*aes_decipher_callback)(uint8_t*, uint32_t), void(*cmac_generate_callback)(uint8_t*, uint32_t, uint8_t*), void (*on_receive_callback)(uint8_t, struct PH_LINK_message*), void (*on_send_callback)(uint8_t*, uint32_t));
void PH_LINK_init_ctx(struct PH_LINK_ctx* ctx, uint32_t tx_sequence, uint32_t rx_sequence, void(*aes_cipher_callback)(uint8_t*, uint32_t), void(*aes_decipher_callback)(uint8_t*, uint32_t), void(*cmac_generate_callback)(uint8_t*, uint32_t, uint8_t*), void (*on_receive_callback)(uint8_t, struct PH_LINK_message*), void (*on_send_callback)(uint8_t*, uint32_t));

uint8_t PH_LINK_send(struct PH_LINK_ctx* ctx, struct PH_LINK_message* msg);
uint8_t PH_LINK_send_list(struct PH_LINK_ctx* ctx, struct PH_LINK_message* msg, uint8_t length);
uint8_t PH_LINK_decode(struct PH_LINK_ctx* ctx, uint32_t length, struct PH_LINK_message* msg);
uint8_t PH_LINK_receive(struct PH_LINK_ctx* ctx, uint8_t* buffer, uint32_t length, struct PH_LINK_message* msg);

#endif // _PH_LINK_H_
