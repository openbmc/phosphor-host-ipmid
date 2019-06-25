#include <sensorhandler.hpp>

#include <gtest/gtest.h>

TEST(SensorHandlerTest, GetSdrReq_get_reservation_id_HappyPath)
{
    uint16_t expected_id = 0x1234;     // Expected ID spans both bytes.
    get_sdr::GetSdrReq input = {0x34,  // Reservation ID LSB
                                0x12,  // Reservation ID MSB
                                0x00,  // Record ID LSB
                                0x00,  // Record ID MSB
                                0x00,  // Offset
                                0x00}; // Bytes to Read

    uint16_t actual = get_sdr::request::get_reservation_id(&input);
    ASSERT_EQ(actual, expected_id);
}

TEST(SensorHandlerTest, GetSdrReq_get_reservation_id_NullInputDies)
{
    ASSERT_DEATH(get_sdr::request::get_reservation_id(nullptr), ".*");
}

TEST(SensorHandlerTest, GetSdrReq_get_reservation_id_Uint16MaxWorksCorrectly)
{
    uint16_t expected_id = 0xFFFF;     // Expected ID spans both bytes.
    get_sdr::GetSdrReq input = {0xFF,  // Reservation ID LSB
                                0xFF,  // Reservation ID MSB
                                0x00,  // Record ID LSB
                                0x00,  // Record ID MSB
                                0x00,  // Offset
                                0x00}; // Bytes to Read

    uint16_t actual = get_sdr::request::get_reservation_id(&input);
    ASSERT_EQ(actual, expected_id);
}

TEST(SensorHandlerTest, GetSdrReq_get_record_id_HappyPath)
{
    uint16_t expected_id = 0x1234;     // Expected ID spans both bytes.
    get_sdr::GetSdrReq input = {0x00,  // Reservation ID LSB
                                0x00,  // Reservation ID MSB
                                0x34,  // Record ID LSB
                                0x12,  // Record ID MSB
                                0x00,  // Offset
                                0x00}; // Bytes to Read

    uint16_t actual = get_sdr::request::get_record_id(&input);
    ASSERT_EQ(actual, expected_id);
}

TEST(SensorHandlerTest, GetSdrReq_get_record_id_NullInputDies)
{
    ASSERT_DEATH(get_sdr::request::get_record_id(nullptr), ".*");
}

TEST(SensorHandlerTest, GetSdrReq_get_record_id_Uint16MaxWorksCorrectly)
{
    uint16_t expected_id = 0xFFFF;     // Expected ID spans both bytes.
    get_sdr::GetSdrReq input = {0x00,  // Reservation ID LSB
                                0x00,  // Reservation ID MSB
                                0xFF,  // Record ID LSB
                                0xFF,  // Record ID MSB
                                0x00,  // Offset
                                0x00}; // Bytes to Read

    uint16_t actual = get_sdr::request::get_record_id(&input);
    ASSERT_EQ(actual, expected_id);
}
