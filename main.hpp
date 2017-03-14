#pragma once

#include <tuple>

#include <command_table.hpp>
#include <sessions_manager.hpp>
#include "sol/sol_manager.hpp"
#include "sd_event_loop.hpp"

extern std::tuple<session::Manager&, command::Table&,
                  eventloop::EventLoop&, sol::Manager&> singletonPool;

// Select call timeout is set arbitarily set to 30 sec
static constexpr size_t SELECT_CALL_TIMEOUT = 30;
static const auto IPMI_STD_PORT = 623;

extern sd_bus* bus;
