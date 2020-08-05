#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "ph_link.h"

void PH_LINK_init_sequences_ctx(struct PH_LINK_ctx* ctx, uint32_t tx_sequence, uint32_t rx_sequence) {
	ctx->tx_sequence = tx_sequence;
	ctx->rx_sequence = rx_sequence;

	ctx->rx_sequence_big_window_active = 0;
	ctx->rx_sequence_big_window_value = 0;
	ctx->rx_sequence_big_window_counter = 0;
}

void PH_LINK_init_buffer_ctx(struct PH_LINK_ctx* ctx, uint8_t* buffer, uint32_t buffer_size) {
	ctx->buffer = buffer;
	ctx->buffer_size = buffer_size;
}

void PH_LINK_init_callbacks_ctx(struct PH_LINK_ctx* ctx, void(*aes_cipher_callback)(uint8_t*, uint32_t), void(*aes_decipher_callback)(uint8_t*, uint32_t), void(*cmac_generate_callback)(uint8_t*, uint32_t, uint8_t*), void (*on_receive_callback)(uint8_t, struct PH_LINK_message*), void (*on_send_callback)(uint8_t*, uint32_t)) {
	ctx->aes_cipher_callback = aes_cipher_callback;
	ctx->aes_decipher_callback = aes_decipher_callback;
	ctx->cmac_generate_callback = cmac_generate_callback;
	ctx->on_receive_callback = on_receive_callback;
	ctx->on_send_callback = on_send_callback;
}

void PH_LINK_init_ctx(struct PH_LINK_ctx* ctx, uint32_t tx_sequence, uint32_t rx_sequence, void(*aes_cipher_callback)(uint8_t*, uint32_t), void(*aes_decipher_callback)(uint8_t*, uint32_t), void(*cmac_generate_callback)(uint8_t*, uint32_t, uint8_t*), void (*on_receive_callback)(uint8_t, struct PH_LINK_message*), void (*on_send_callback)(uint8_t*, uint32_t)) {
	PH_LINK_init_callbacks_ctx(ctx, aes_cipher_callback, aes_decipher_callback, cmac_generate_callback, on_receive_callback, on_send_callback);
	PH_LINK_init_sequences_ctx(ctx, tx_sequence, rx_sequence);
}

/* Decodes the payload from ctx.buffer into PH_LINK_message and calls the on_receive_callback if defined */
uint8_t PH_LINK_decode(struct PH_LINK_ctx* ctx, uint32_t length, struct PH_LINK_message* msg) {
	return PH_LINK_receive(ctx, ctx->buffer, length, msg);
}

/* Decodes the payload from provided buffer into PH_LINK_message and calls the on_receive_callback if defined */
uint8_t PH_LINK_receive(struct PH_LINK_ctx* ctx, uint8_t* buffer, uint32_t length, struct PH_LINK_message* msg) {
	if (length > ctx->buffer_size) return PH_LINK_RX_NO_MEMORY;

	// structure: encrypted{ [RANDOM] [SEQUENCE] [PADDING_SIZE] [DATA + PADDING(0-15)] } [CMAC]

	// first verify the ciphertext CMAC
	uint8_t cmac[PH_LINK_CMAC_SIZE];

	// generate the CMAC from received ciphertext and verify
	ctx->cmac_generate_callback(buffer, length - PH_LINK_CMAC_SIZE, cmac);
	if (memcmp(cmac, buffer - PH_LINK_CMAC_SIZE, PH_LINK_CMAC_SIZE) == 0) {
		return PH_LINK_RX_CMAC_INVALID;
	}

	uint8_t rx_status = PH_LINK_RX_OK;

	// decrypt it "in place"
	ctx->aes_decipher_callback(buffer, length - PH_LINK_CMAC_SIZE);

	uint8_t* buffer_ptr = buffer;

	// extract fields from the payload
	// skip the "random", we don't need it and it would be dangerous to have meaningful data in this field. don't even think about it
	buffer_ptr += PH_LINK_RANDOM_IV_SIZE;

	// extract the sequence value
	uint32_t sequence;
	memcpy(&sequence, buffer_ptr, PH_LINK_SEQUENCE_SIZE); // note: endianness
	buffer_ptr += PH_LINK_SEQUENCE_SIZE;

	// verify the sequence value
	uint8_t edgeSkipWin = (ctx->rx_sequence + (uint32_t)PH_LINK_SEQUENCE_RX_RESYNC_SKIP_WINDOW) < ctx->rx_sequence; // check for overflown sequence
	uint8_t edgeBigWin = (ctx->rx_sequence + (uint32_t)PH_LINK_SEQUENCE_RX_RESYNC_BIG_WINDOW) < ctx->rx_sequence; // check for overflown sequence
	// sequence is spot on!
	if (sequence == ctx->rx_sequence) {
		//rx_status = PH_LINK_RX_OK;
	}
	// within the skip window, handle overflow (edge)
	else if (
		(!edgeSkipWin && (sequence > ctx->rx_sequence) && (sequence < ctx->rx_sequence + PH_LINK_SEQUENCE_RX_RESYNC_SKIP_WINDOW)) // middle
		|| (edgeSkipWin && (sequence > ctx->rx_sequence) && (sequence < PH_LINK_MAX_SEQUENCE_VALUE)) // trailing overflow
		|| (edgeSkipWin && (sequence > 0) && (sequence < PH_LINK_SEQUENCE_RX_RESYNC_SKIP_WINDOW - (PH_LINK_MAX_SEQUENCE_VALUE - ctx->rx_sequence)))) { // leading overflow
		ctx->rx_sequence = sequence;
		rx_status = PH_LINK_RX_OK_RESYNC_SKIP_WIN;
	}
	// within the re-sync big window, handle overflow (edge)
	else if ((!edgeBigWin &&
		(sequence > ctx->rx_sequence) && (sequence < ctx->rx_sequence + PH_LINK_SEQUENCE_RX_RESYNC_BIG_WINDOW)) // middle
		|| (edgeBigWin && (sequence > ctx->rx_sequence) && (sequence < PH_LINK_MAX_SEQUENCE_VALUE)) // trailing overflow
		|| (edgeBigWin && (sequence > 0) && (sequence < PH_LINK_SEQUENCE_RX_RESYNC_BIG_WINDOW - (PH_LINK_MAX_SEQUENCE_VALUE - ctx->rx_sequence)))) { // leading overflow

		// start synchronizing within the "big window"?
		if (ctx->rx_sequence_big_window_active == 0) {
			ctx->rx_sequence_big_window_active = 1;
			ctx->rx_sequence_big_window_value = sequence + 1;
			ctx->rx_sequence_big_window_counter = 0;
		}
		// check if sequence is received as expected for the "big window" re-sync
		else if (sequence == ctx->rx_sequence_big_window_value) {
			ctx->rx_sequence_big_window_value++;
			ctx->rx_sequence_big_window_counter++;
		}
		// failure, cancel currently active "big window" re-sync
		else {
			ctx->rx_sequence_big_window_active = 0;
		}

		// finally re-synced?
		if (ctx->rx_sequence_big_window_counter == PH_LINK_SEQUENCE_RX_RESYNC_BIG_WINDOW_COUNTER) {
			rx_status = PH_LINK_RX_OK_RESYNC_BIG_WIN;
			ctx->rx_sequence = sequence; // re-sync!
		}
		// not yet
		else {
			return PH_LINK_RX_SEQUENCE_BIGWIN_ACTIVE;
		}
	}
	// re-transmission
	else if (sequence < ctx->rx_sequence) {
		return PH_LINK_RX_SEQUENCE_ERR;
	}

	// sequence value was evaluated as OK
	ctx->rx_sequence++;
	ctx->rx_sequence_big_window_active = 0;

	// extract the padding size
	uint8_t padding_size;
	memcpy(&padding_size, buffer_ptr, PH_LINK_PADDING_LENGTH_SIZE);
	buffer_ptr += PH_LINK_PADDING_LENGTH_SIZE;

	// calculate the length of data without the padding and cmac at the end
	uint32_t data_length = length - (buffer_ptr - buffer) - padding_size - PH_LINK_CMAC_SIZE;

	// extract the data, until the padding and put into provided msg.data buffer
	memcpy(msg->data, buffer_ptr, data_length);
	msg->length = data_length;

	if (ctx->on_receive_callback != NULL) {
		ctx->on_receive_callback(rx_status, msg);
	}

	return rx_status;
}

/* Sends the message "msg" to recepient. returns 0 on success, >0 on exception */
uint8_t PH_LINK_send(struct PH_LINK_ctx* ctx, struct PH_LINK_message* msg) {
	if (ctx->on_send_callback == NULL) return PH_LINK_TX_CALLBACK_UNDEFINED;

	// structure: encrypted{ [RANDOM] [SEQUENCE] [PADDING_SIZE] [DATA + PADDING(0-15)] } [CMAC]

	uint8_t tx_status = PH_LINK_TX_OK;

	uint32_t payload_size = PH_LINK_RANDOM_IV_SIZE + PH_LINK_SEQUENCE_SIZE + PH_LINK_PADDING_LENGTH_SIZE + msg->length;

	// adjust the length to 16 byte blocks in order to encrypt with AES
	uint8_t ps16 = payload_size % 16;
	uint8_t padding_size = (ps16 > 0) ? 16 - ps16 : 0;

	payload_size += padding_size;

	#if PH_LINK_CMAC_SIZE > 16
		#error "PH_LINK_CMAC_SIZE must be less or equal to 16"
	#endif
	#if PH_LINK_CMAC_SIZE < 1
		#error "PH_LINK_CMAC_SIZE must be larger than 0"
	#endif

	// will there be enough memory to store everything?
	if (payload_size + PH_LINK_CMAC_SIZE > ctx->buffer_size) return PH_LINK_TX_NO_MEMORY;

	uint8_t* buffer_ptr = ctx->buffer;

	// copy random IV to beginning of to-be encrypted data
	ctx->random_callback(buffer_ptr, PH_LINK_RANDOM_IV_SIZE);
	buffer_ptr += PH_LINK_RANDOM_IV_SIZE;

	// copy tx sequence after the payload length field
	memcpy(buffer_ptr, &(ctx->tx_sequence), PH_LINK_SEQUENCE_SIZE); // note: endianness
	buffer_ptr += PH_LINK_SEQUENCE_SIZE;

	ctx->tx_sequence++; // next sequence no
	if (ctx->tx_sequence == 0) {
		tx_status = PH_LINK_TX_OK_SEQUENCE_OVERFLOWN;
	}

	// copy length of padding that we might have added to the data
	memcpy(buffer_ptr, &(padding_size), PH_LINK_PADDING_LENGTH_SIZE);
	buffer_ptr += PH_LINK_PADDING_LENGTH_SIZE;

	// now copy message contents (+padding if any) to our PH_LINK working buffer
	memcpy(buffer_ptr, msg->data, msg->length);
	buffer_ptr += msg->length;

	// lets randomize the padded data, just in case for security purposes
	ctx->random_callback(buffer_ptr, padding_size);
	buffer_ptr += padding_size;

	// encrypt entire payload
	ctx->aes_cipher_callback(ctx->buffer, payload_size);

	// generate the MAC from entire buffer and put it at the end of the message
	ctx->cmac_generate_callback(ctx->buffer, payload_size, buffer_ptr);

	// done, call the callback dedicated to dump the payload to transport "stream"
	ctx->on_send_callback(ctx->buffer, payload_size + PH_LINK_CMAC_SIZE);

	return tx_status;
}

/* Send list of messages **msg to recipient. return 0 on success, >0 for first message with exception in the list. will break on first TX error */
uint8_t PH_LINK_send_list(struct PH_LINK_ctx* ctx, struct PH_LINK_message* msg, uint8_t length) {
	uint8_t tx_status = PH_LINK_TX_OK;
	for (uint8_t i = 0; i < length; i++) {
		uint8_t txs = PH_LINK_send(ctx, &msg[i]);
		if (txs >= _PH_LINK_TX_MIN_ERROR_VALUE) return txs;
		else if (txs != PH_LINK_TX_OK) tx_status = txs;
	}

	return tx_status;
}
