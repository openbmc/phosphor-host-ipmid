#include <stdint.h>

void send_esel(uint16_t recordid);

/** @brief Read eSEL data into a string
 *
 *  @param[in] filename - filename of file containing eSEL
 *
 *  @return On success return the eSEL data
 */
std::string readESEL(const char* filename);

/** @brief Create a log entry with maintenance procedure
 *
 *  @param[in] procedureNum - procedure number associated with the log entry
 */
void createProcedureLogEntry(uint8_t procedureNum);
