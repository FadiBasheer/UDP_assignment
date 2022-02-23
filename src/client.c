#include "echo.h"
#include <assert.h>
#include <dc_application/command_line.h>
#include <dc_application/config.h>
#include <dc_application/options.h>
#include <dc_posix/dc_netdb.h>
#include <dc_posix/dc_stdlib.h>
#include <dc_posix/dc_string.h>
#include <dc_posix/dc_unistd.h>
#include <dc_posix/sys/dc_socket.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX 80
#define MAXLINE 1024

struct application_settings {
    struct dc_opt_settings opts;
    struct dc_setting_bool *verbose;
    struct dc_setting_string *hostname;
    struct dc_setting_regex *ip_version;
    struct dc_setting_uint16 *port;

    struct dc_setting_uint16 *packet_size;
    struct dc_setting_uint16 *delay;
    struct dc_setting_string *starting_time;
    struct dc_setting_uint16 *packet_number;
};

struct TIME {
    int seconds;
    int minutes;
    int hours;
};

int UDP_client(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err,
               struct dc_application_settings *settings);

uint16_t Calculate_starting_time(char *starting_time);

uint16_t differenceBetweenTimePeriod(struct TIME start,
                                     struct TIME stop,
                                     struct TIME *diff);

static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err);

static int
destroy_settings(const struct dc_posix_env *env, struct dc_error *err,
                 struct dc_application_settings **psettings);

static int run(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings *settings);

int main(int argc, char *argv[]) {
    dc_posix_tracer tracer;
    dc_error_reporter reporter;
    struct dc_posix_env env;
    struct dc_error err;
    struct dc_application_info *info;
    int ret_val;

    tracer = dc_posix_default_tracer;
    dc_posix_env_init(&env, tracer);
    reporter = dc_error_default_error_reporter;
    dc_error_init(&err, reporter);
    info = dc_application_info_create(&env, &err, "Test Application");
    ret_val = dc_application_run(&env, &err, info, create_settings, destroy_settings, run, dc_default_create_lifecycle,
                                 dc_default_destroy_lifecycle,
                                 "~/.dcecho.conf",
                                 argc, argv);
    dc_application_info_destroy(&env, &info);
    dc_error_reset(&err);

    return ret_val;
}

static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err) {
    static const bool default_verbose = false;
    static const char *default_hostname = "localhost";
    static const char *default_ip = "IPv4";
    static const uint16_t default_port = DEFAULT_ECHO_PORT;
    static const uint16_t default_Packet_SIZE = 25;
    static const uint16_t default_Packet_number = 10;
    static const uint16_t default_Starting_time = 0;
    static const uint16_t default_Delay = 50;
    struct application_settings *settings;

    settings = dc_malloc(env, err, sizeof(struct application_settings));

    if (settings == NULL) {
        return NULL;
    }

    settings->opts.parent.config_path = dc_setting_path_create(env, err);
    settings->verbose = dc_setting_bool_create(env, err);
    settings->hostname = dc_setting_string_create(env, err);
    settings->ip_version = dc_setting_regex_create(env, err, "^IPv[4|6]");
    settings->port = dc_setting_uint16_create(env, err);
    settings->packet_size = dc_setting_uint16_create(env, err);
    settings->packet_number = dc_setting_uint16_create(env, err);
    settings->starting_time = dc_setting_string_create(env, err);
    settings->delay = dc_setting_uint16_create(env, err);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
    struct options opts[] =
            {
                    {(struct dc_setting *) settings->opts.parent.config_path, dc_options_set_path,   "config",        required_argument, 'c', "CONFIG",        dc_string_from_string, NULL,            dc_string_from_config, NULL},
                    {(struct dc_setting *) settings->verbose,                 dc_options_set_bool,   "verbose",       no_argument,       'v', "VERBOSE",       dc_flag_from_string,   "verbose",       dc_flag_from_config,   &default_verbose},
                    {(struct dc_setting *) settings->hostname,                dc_options_set_string, "host",          required_argument, 'h', "HOST",          dc_string_from_string, "host",          dc_string_from_config, default_hostname},
                    {(struct dc_setting *) settings->ip_version,              dc_options_set_regex,  "ip",            required_argument, 'i', "IP",            dc_string_from_string, "ip",            dc_string_from_config, default_ip},
                    {(struct dc_setting *) settings->port,                    dc_options_set_uint16, "port",          required_argument, 'p', "PORT",          dc_uint16_from_string, "port",          dc_uint16_from_config, &default_port},
                    {(struct dc_setting *) settings->packet_size,             dc_options_set_uint16, "packet_size",   required_argument, 'm', "PACKET_SIZE",   dc_uint16_from_string, "packet_size",   dc_uint16_from_config, &default_Packet_SIZE},
                    {(struct dc_setting *) settings->packet_number,           dc_options_set_uint16, "packet_number", required_argument, 'm', "PACKET_NUMBER", dc_uint16_from_string, "packet_number", dc_uint16_from_config, &default_Packet_number},
                    {(struct dc_setting *) settings->starting_time,           dc_options_set_string, "starting_time", required_argument, 'm', "STARTING_TIME", dc_string_from_string, "starting_time", dc_string_from_config, &default_Starting_time},
                    {(struct dc_setting *) settings->delay,                   dc_options_set_uint16, "delay",         required_argument, 'm', "DELAY",         dc_uint16_from_string, "delay",         dc_uint16_from_config, &default_Delay},
            };
#pragma GCC diagnostic pop

    // note the trick here - we use calloc and add 1 to ensure the last line is all 0/NULL
    settings->opts.opts = dc_calloc(env, err, (sizeof(opts) / sizeof(struct options)) + 1, sizeof(struct options));
    dc_memcpy(env, settings->opts.opts, opts, sizeof(opts));
    settings->opts.flags = "c:vh:i:p:m:";
    settings->opts.env_prefix = "DC_ECHO_";

    return (struct dc_application_settings *) settings;
}

static int destroy_settings(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err,
                            struct dc_application_settings **psettings) {
    struct application_settings *app_settings;

    app_settings = (struct application_settings *) *psettings;
    dc_setting_bool_destroy(env, &app_settings->verbose);
    dc_setting_string_destroy(env, &app_settings->hostname);
    dc_setting_regex_destroy(env, &app_settings->ip_version);
    dc_setting_uint16_destroy(env, &app_settings->port);
    dc_setting_uint16_destroy(env, &app_settings->packet_size);
    dc_setting_uint16_destroy(env, &app_settings->packet_number);
    dc_setting_string_destroy(env, &app_settings->starting_time);
    dc_setting_uint16_destroy(env, &app_settings->delay);
    dc_free(env, app_settings->opts.opts, app_settings->opts.opts_size);
    dc_free(env, app_settings, sizeof(struct application_settings));

    if (env->null_free) {
        *psettings = NULL;
    }
    return 0;
}

static int run(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err,
               struct dc_application_settings *settings) {
    struct application_settings *app_settings;
    const uint16_t packet_size;
    bool verbose;
    const char *hostname;
    const char *starting_time;
    const char *ip_version;
    in_port_t port;
    uint16_t Packet_Size;
    uint16_t Packet_Number;
    int ret_val;
    struct addrinfo hints;
    struct addrinfo *result;
    int family;
    int sock_fd;
    socklen_t size;
    size_t message_length;
    uint16_t converted_port;

    app_settings = (struct application_settings *) settings;

    verbose = dc_setting_bool_get(env, app_settings->verbose);
    hostname = dc_setting_string_get(env, app_settings->hostname);
    ip_version = dc_setting_regex_get(env, app_settings->ip_version);
    port = dc_setting_uint16_get(env, app_settings->port);
    starting_time = dc_setting_string_get(env, app_settings->starting_time);
    Packet_Size = dc_setting_uint16_get(env, app_settings->packet_size);
    Packet_Number = dc_setting_uint16_get(env, app_settings->packet_number);
    ret_val = 0;

    if (verbose) {
        fprintf(stderr, "Connecting to %s @ %" PRIu16 " via %s\n", hostname, port, ip_version);
    }

    if (dc_strcmp(env, ip_version, "IPv4") == 0) {
        family = PF_INET;
    } else {
        if (dc_strcmp(env, ip_version, "IPv6") == 0) {
            family = PF_INET6;
        } else {
            assert("Can't get here" != NULL);
            family = 0;
        }
    }

    dc_memset(env, &hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    dc_getaddrinfo(env, err, hostname, NULL, &hints, &result);

    if (dc_error_has_error(err)) {
        return -1;
    }

    sock_fd = dc_socket(env, err, result->ai_family, result->ai_socktype, result->ai_protocol);

    if (dc_error_has_error(err)) {
        return -1;
    }

    // NOLINTNEXTLINE(hicpp-signed-bitwise)
    converted_port = htons(port);

    if (dc_strcmp(env, ip_version, "IPv4") == 0) {
        struct sockaddr_in *sockaddr;

        sockaddr = (struct sockaddr_in *) result->ai_addr;
        sockaddr->sin_port = converted_port;
        size = sizeof(struct sockaddr_in);
    } else {
        if (dc_strcmp(env, ip_version, "IPv6") == 0) {
            struct sockaddr_in6 *sockaddr;

            sockaddr = (struct sockaddr_in6 *) result->ai_addr;
            sockaddr->sin6_port = converted_port;
            size = sizeof(struct sockaddr_in);
        } else {
            assert("Can't get here" != NULL);
            size = 0;
        }
    }

    dc_connect(env, err, sock_fd, result->ai_addr, size);

    if (dc_error_has_error(err)) {
        return -1;
    }

    // Calculated_starting_time
    uint16_t Calculated_starting_time = 0;

    if (strcmp(starting_time, "") != 0) {
        Calculated_starting_time = Calculate_starting_time(starting_time);
    }

    if (dc_error_has_no_error(err)) {
        char buff[MAX];
        char *str;
        memset(buff, 0, MAX);

        str = strdup("");
        sprintf(str, "%d %d %d%c", Calculated_starting_time, Packet_Size, Packet_Number, '\0');

        // Sending first message
        dc_write(env, err, sock_fd, str, strlen(str) + 1);
        read(sock_fd, buff, sizeof(buff));

        memset(buff, 0, MAX);

        // Waiting until the time specified
        sleep((unsigned int) Calculated_starting_time);

        // Run UDP
        UDP_client(env, err, settings);

        // Sending final message to tell the server that the client is done
        dc_write(env, err, sock_fd, "exit", sizeof("exit"));
        read(sock_fd, buff, sizeof(buff));
    }
    return ret_val;
}

/*
 * UDP part
 */
int UDP_client(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err,
               struct dc_application_settings *settings) {
    struct application_settings *app_settings;
    uint16_t delay;
    uint16_t packet_size;
    uint16_t packet_number;
    const char *hostname;
    in_port_t port;

    app_settings = (struct application_settings *) settings;
    port = dc_setting_uint16_get(env, app_settings->port);
    hostname = dc_setting_string_get(env, app_settings->hostname);
    delay = dc_setting_uint16_get(env, app_settings->delay);
    packet_size = dc_setting_uint16_get(env, app_settings->packet_size);
    packet_number = dc_setting_uint16_get(env, app_settings->packet_number);

    int sockfd;
    char *str;

    /* Initial memory allocation */
    str = (char *) malloc(packet_size);
    char *temp[packet_size - 3];
    memset(temp, '1', packet_size - 3);


    struct sockaddr_in servaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    inet_pton(AF_INET, hostname, &servaddr.sin_addr);

    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = delay * 10000000;

    for (int i = 0; i < packet_number; ++i) {
        sprintf(str, "%d %s%c", i, temp, '\0');
        sendto(sockfd, (const char *) str, strlen(str),
               MSG_CONFIRM, (const struct sockaddr *) &servaddr,
               sizeof(servaddr));
        printf("Sending: %s\n", str);
        nanosleep(&ts, NULL);
    }
    close(sockfd);
    return 0;
}

//Calculating the starting time
uint16_t Calculate_starting_time(char *starting_time) {
    struct TIME startTime, stopTime, diff;

    int comming_time[2];
    int current_hr, current_mn, i = 0;
    char delim[] = ":";

    char *ptr = strtok(starting_time, delim);

    while (ptr != NULL) {
        comming_time[i] = atoi(ptr);
        ptr = strtok(NULL, delim);
        i++;
    }
    startTime.hours = comming_time[0];
    startTime.minutes = comming_time[1];
    startTime.seconds = 0;

    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    current_hr = timeinfo->tm_hour;
    current_mn = timeinfo->tm_min;

    stopTime.hours = current_hr;
    stopTime.minutes = current_mn;
    stopTime.seconds = 0;

    uint16_t rt;
    rt = differenceBetweenTimePeriod(startTime, stopTime, &diff);
    return rt;
}

uint16_t differenceBetweenTimePeriod(struct TIME start,
                                     struct TIME stop,
                                     struct TIME *diff) {
    uint16_t s;
    while (stop.seconds > start.seconds) {
        --start.minutes;
        start.seconds += 60;
    }
    diff->seconds = start.seconds - stop.seconds;
    s = (uint16_t) diff->seconds;
    while (stop.minutes > start.minutes) {
        --start.hours;
        start.minutes += 60;
    }
    diff->minutes = start.minutes - stop.minutes;
    diff->hours = start.hours - stop.hours;

    s += diff->minutes * 60;
    s += diff->hours * 3600;
    return s;
}
