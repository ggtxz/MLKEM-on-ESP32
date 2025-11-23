#include "uart.h"

static const char *LOG_TAG = "UART_COMM";

void uart_free_frame(frame_t *frame)
{
    if (frame == NULL) {
        return;
    }

    if (frame->payload != NULL) {
        free(frame->payload);
        frame->payload = NULL;
    }

    frame->frame_type  = 0;
    frame->payload_len = 0;
    memset(frame->hmac, 0, HMAC_SIZE);
}

void uart_setup(void)
{
    const uart_config_t config = {
        .baud_rate = 9600,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    };

    esp_err_t err;

    err = uart_driver_install(
        UART_PORT,
        UART_BUFFER_SIZE * 2,   // RX buffer
        UART_BUFFER_SIZE * 2,   // TX buffer
        0,
        NULL,
        0
    );
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "uart_driver_install falhou: %s", esp_err_to_name(err));
        return;
    }

    err = uart_param_config(UART_PORT, &config);
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "uart_param_config falhou: %s", esp_err_to_name(err));
        return;
    }

    err = uart_set_pin(
        UART_PORT,
        UART_TX_PIN,
        UART_RX_PIN,
        UART_PIN_NO_CHANGE,
        UART_PIN_NO_CHANGE
    );
    if (err != ESP_OK) {
        ESP_LOGE(LOG_TAG, "uart_set_pin falhou: %s", esp_err_to_name(err));
        return;
    }
}

int uart_read_data(frame_t *frame)
{
    if (frame == NULL) {
        return INVALID_FRAME;
    }

    uint8_t byte;
    int retries = 0;

    // Garante estado conhecido
    uart_free_frame(frame);

    while (retries < MAX_RETRIES) {
        int r;

        // 1) Primeiro byte do cabeçalho
        r = uart_read_bytes(UART_PORT, &byte, 1, TICK_PERIOD_MS);
        if (r != 1) {
            retries++;
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        if (byte != UART_HEADER_BYTE1) {
            retries++;
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        // 2) Segundo byte do cabeçalho
        r = uart_read_bytes(UART_PORT, &byte, 1, TICK_PERIOD_MS);
        if (r != 1) {
            retries++;
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        if (byte != UART_HEADER_BYTE2) {
            retries++;
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        // 3) Tipo de frame
        r = uart_read_bytes(
            UART_PORT,
            (uint8_t *)&frame->frame_type,
            sizeof(frame->frame_type),
            TICK_PERIOD_MS
        );
        if (r != sizeof(frame->frame_type)) {
            retries++;
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        // 4) Tamanho do payload
        r = uart_read_bytes(
            UART_PORT,
            (uint8_t *)&frame->payload_len,
            sizeof(frame->payload_len),
            TICK_PERIOD_MS
        );
        if (r != sizeof(frame->payload_len)) {
            retries++;
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        // 5) Payload
        if (frame->payload_len == 0) {
            // Frame de controle (SYN/ACK/NACK) não carrega payload
            frame->payload = NULL;
        } else {
            frame->payload = calloc(frame->payload_len, 1);
            if (frame->payload == NULL) {
                ESP_LOGE(LOG_TAG, "Falha ao alocar memória para payload (len=%u)",
                         frame->payload_len);
                return MEM_ERR;
            }

            size_t received = 0;
            while (received < frame->payload_len) {
                r = uart_read_bytes(
                    UART_PORT,
                    frame->payload + received,
                    frame->payload_len - received,
                    TICK_PERIOD_MS
                );
                if (r <= 0) {
                    retries++;
                    uart_free_frame(frame);
                    break;
                }
                received += r;
            }

            if (received < frame->payload_len) {
                // Não conseguiu ler tudo, tenta de novo
                continue;
            }
        }

        // 6) HMAC
        size_t hmac_received = 0;
        while (hmac_received < HMAC_SIZE) {
            r = uart_read_bytes(
                UART_PORT,
                &frame->hmac[hmac_received],
                HMAC_SIZE - hmac_received,
                TICK_PERIOD_MS
            );
            if (r <= 0) {
                retries++;
                uart_free_frame(frame);
                break;
            }
            hmac_received += r;
        }

        if (hmac_received < HMAC_SIZE) {
            // HMAC incompleto, tenta novo frame
            continue;
        }

        // Frame completo lido com sucesso
        return SUCCESS;
    }

    return TIMEOUT_ERR;
}

void uart_send_data(const frame_t *frame)
{
    if (frame == NULL) {
        return;
    }

    const unsigned char header[UART_HEADER_SIZE] = {
        UART_HEADER_BYTE1,
        UART_HEADER_BYTE2
    };

    // 1) Cabeçalho
    uart_write_bytes(UART_PORT, (const char *)header, UART_HEADER_SIZE);

    // 2) Tipo
    uart_write_bytes(
        UART_PORT,
        (const char *)&frame->frame_type,
        sizeof(frame->frame_type)
    );

    // 3) Tamanho do payload
    uart_write_bytes(
        UART_PORT,
        (const char *)&frame->payload_len,
        sizeof(frame->payload_len)
    );

    // 4) Payload criptografado (se existir)
    if (frame->payload_len > 0 && frame->payload != NULL) {
        uart_write_bytes(
            UART_PORT,
            (const char *)frame->payload,
            frame->payload_len
        );
    }

    // 5) HMAC
    uart_write_bytes(
        UART_PORT,
        (const char *)frame->hmac,
        HMAC_SIZE
    );
}

void uart_ack_send(void)
{
    frame_t ack_frame = {0};

    ack_frame.payload     = NULL;
    ack_frame.frame_type  = FRAME_TYPE_ACK;
    ack_frame.payload_len = 0;                // ACK sem payload
    memset(ack_frame.hmac, 0, HMAC_SIZE);     // HMAC vazio (ou poderia ter HMAC real se quiser)

    uart_send_data(&ack_frame);
    uart_free_frame(&ack_frame);
}

void uart_nack_send(void)
{
    frame_t nack_frame = {0};

    nack_frame.payload     = NULL;
    nack_frame.frame_type  = FRAME_TYPE_NACK;
    nack_frame.payload_len = 0;               // NACK sem payload
    memset(nack_frame.hmac, 0, HMAC_SIZE);

    uart_send_data(&nack_frame);
    uart_free_frame(&nack_frame);
}

int uart_ack_check(void)
{
    int max_retries = 10;
    int retries     = 0;
    frame_t ack_frame = {0};

    while (retries < max_retries) {
        int status = uart_read_data(&ack_frame);

        if (status == SUCCESS) {
            if (ack_frame.payload == NULL &&
                ack_frame.payload_len == 0 &&
                ack_frame.frame_type == FRAME_TYPE_ACK) {

                uart_free_frame(&ack_frame);
                return FRAME_TYPE_ACK;
            }

            if (ack_frame.payload == NULL &&
                ack_frame.payload_len == 0 &&
                ack_frame.frame_type == FRAME_TYPE_NACK) {

                uart_free_frame(&ack_frame);
                return FRAME_TYPE_NACK;
            }
            
            uart_free_frame(&ack_frame);
            return INVALID_FRAME;
        }

        retries++;
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    return TIMEOUT_ERR;
}

int uart_threeway_handshake_init(void)
{
    frame_t syn_frame = {0};

    syn_frame.payload     = NULL;
    syn_frame.frame_type  = FRAME_TYPE_SYN;
    syn_frame.payload_len = 0;               // SYN sem payload
    memset(syn_frame.hmac, 0, HMAC_SIZE);    // HMAC vazio

    uart_send_data(&syn_frame);
    uart_free_frame(&syn_frame);

    int ack = uart_ack_check();

    if (ack == FRAME_TYPE_ACK) {
        uart_ack_send();
        return SUCCESS;
    }

    if (ack == FRAME_TYPE_NACK) {
        return TIMEOUT_ERR;
    }

    return TIMEOUT_ERR;
}

int uart_threeway_handshake_receive(void)
{
    frame_t received_frame = {0};

    int status = uart_read_data(&received_frame);
    if (status != SUCCESS) {
        return TIMEOUT_ERR;
    }

    if (received_frame.payload == NULL &&
        received_frame.payload_len == 0 &&
        received_frame.frame_type == FRAME_TYPE_SYN) {

        uart_free_frame(&received_frame);

        // Envia ACK
        uart_ack_send();

        // Espera o ACK final
        int ack_final = uart_ack_check();
        if (ack_final == FRAME_TYPE_ACK) {
            return SUCCESS;
        }

        return TIMEOUT_ERR;
    }

    uart_free_frame(&received_frame);
    return INVALID_FRAME;
}
