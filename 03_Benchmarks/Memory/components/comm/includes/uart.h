#pragma once

#include "common.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define UART_PORT    UART_NUM_2
#define UART_TX_PIN  GPIO_NUM_17   // TX2
#define UART_RX_PIN  GPIO_NUM_16   // RX2
#define UART_BUFFER_SIZE    1024

#define UART_HEADER_SIZE    2
#define UART_HEADER_BYTE1   0xAA
#define UART_HEADER_BYTE2   0x55

// Tipos de frame
#define FRAME_TYPE_DATA     10      // novo tipo para payload de dados
#define FRAME_TYPE_SYN      0
#define FRAME_TYPE_ACK      1
#define FRAME_TYPE_NACK     999

#define MAX_RETRIES         10

// timeout de leitura do UART em ticks
#define TICK_PERIOD_MS      pdMS_TO_TICKS(20)

// Códigos de retorno genéricos
enum {
    SUCCESS       = 0,
    TIMEOUT_ERR   = -1,
    INVALID_FRAME = -2,
    MEM_ERR       = -3
};

// Novo formato de frame:
// - frame_type: tipo do frame (DATA/SYN/ACK/NACK)
// - payload_len: tamanho do payload em bytes (== tamanho da msg plaintext == tamanho da ciphertext em CTR)
// - payload: ponteiro para o buffer (pode ser NULL se payload_len == 0)
// - hmac: tag HMAC-SHA256 calculada sobre o frame (header + tipo + len + payload, etc.)
typedef struct {
    uint16_t       frame_type;   // FRAME_TYPE_DATA, FRAME_TYPE_SYN, FRAME_TYPE_ACK, FRAME_TYPE_NACK
    uint16_t       payload_len;  // tamanho real do payload (0 para SYN/ACK/NACK)
    unsigned char *payload;      // buffer alocado contendo bytes criptografados (ou NULL se não houver)
    unsigned char  hmac[HMAC_SIZE]; // HMAC recebido ou a enviar
} frame_t;

void uart_setup(void);
int  uart_read_data(frame_t *frame);
void uart_send_data(const frame_t *frame);
void uart_free_frame(frame_t *frame);

void uart_ack_send(void);
void uart_nack_send(void);
int  uart_ack_check(void);

int  uart_threeway_handshake_init(void);
int  uart_threeway_handshake_receive(void);
