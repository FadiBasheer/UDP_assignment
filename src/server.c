#include "echo.h"
#include <dc_application/command_line.h>
#include <dc_application/config.h>
#include <dc_application/options.h>
#include <dc_network/common.h>
#include <dc_network/options.h>
#include <dc_network/server.h>
#include <dc_posix/dc_netdb.h>
#include <dc_posix/dc_signal.h>
#include <dc_posix/dc_string.h>
#include <dc_util/dump.h>
#include <dc_util/streams.h>
#include <getopt.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <wait.h>
#include <fcntl.h>
#include <netdb.h>

#define MAXLINE 1024

struct application_settings {
    struct dc_opt_settings opts;
    struct dc_setting_bool *verbose;
    struct dc_setting_string *hostname;
    struct dc_setting_regex *ip_version;
    struct dc_setting_uint16 *port;
    struct dc_setting_bool *reuse_address;
    struct addrinfo *address;
    int server_socket_fd;
    uint16_t packet_number;
};

static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err);

static int
destroy_settings(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings **psettings);

static int run(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings *settings);

static void signal_handler(int signnum);

static void do_create_settings(const struct dc_posix_env *env, struct dc_error *err, void *arg);

static void do_create_socket(const struct dc_posix_env *env, struct dc_error *err, void *arg);

static void do_set_sockopts(const struct dc_posix_env *env, struct dc_error *err, void *arg);

static void do_bind(const struct dc_posix_env *env, struct dc_error *err, void *arg);

static void do_listen(const struct dc_posix_env *env, struct dc_error *err, void *arg);

static void do_setup(const struct dc_posix_env *env, struct dc_error *err, void *arg);

static bool do_accept(const struct dc_posix_env *env, struct dc_error *err, int *client_socket_fd, void *arg);

static void do_shutdown(const struct dc_posix_env *env, struct dc_error *err, void *arg);

static void do_destroy_settings(const struct dc_posix_env *env, struct dc_error *err, void *arg);


// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t exit_signal = 0;

int main(int argc, char *argv[]) {
    dc_posix_tracer tracer;
    dc_error_reporter reporter;
    struct dc_posix_env env;
    struct dc_error err;
    struct dc_application_info *info;
    int ret_val;
    struct sigaction sa;

    tracer = dc_posix_default_tracer;
    tracer = NULL;
    dc_posix_env_init(&env, tracer);
    reporter = dc_error_default_error_reporter;
    dc_error_init(&err, reporter);
    dc_memset(&env, &sa, 0, sizeof(sa));
    sa.sa_handler = &signal_handler;
    sa.sa_flags = 0;
    dc_sigaction(&env, &err, SIGINT, &sa, NULL);
    dc_sigaction(&env, &err, SIGTERM, &sa, NULL);

    info = dc_application_info_create(&env, &err, "Echo Server");
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
    static const bool default_reuse = false;
    struct application_settings *settings;

    DC_TRACE(env);
    settings = dc_malloc(env, err, sizeof(struct application_settings));

    if (settings == NULL) {
        return NULL;
    }

    settings->opts.parent.config_path = dc_setting_path_create(env, err);
    settings->verbose = dc_setting_bool_create(env, err);
    settings->hostname = dc_setting_string_create(env, err);
    settings->ip_version = dc_setting_regex_create(env, err, "^IPv[4|6]");
    settings->port = dc_setting_uint16_create(env, err);
    settings->reuse_address = dc_setting_bool_create(env, err);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
    struct options opts[] =
            {
                    {(struct dc_setting *) settings->opts.parent.config_path, dc_options_set_path,   "config",  required_argument, 'c', "CONFIG",        dc_string_from_string, NULL,            dc_string_from_config, NULL},
                    {(struct dc_setting *) settings->verbose,                 dc_options_set_bool,   "verbose", no_argument,       'v', "VERBOSE",       dc_flag_from_string,   "verbose",       dc_flag_from_config,   &default_verbose},
                    {(struct dc_setting *) settings->hostname,                dc_options_set_string, "host",    required_argument, 'h', "HOST",          dc_string_from_string, "host",          dc_string_from_config, default_hostname},
                    {(struct dc_setting *) settings->ip_version,              dc_options_set_regex,  "ip",      required_argument, 'i', "IP",            dc_string_from_string, "ip",            dc_string_from_config, default_ip},
                    {(struct dc_setting *) settings->port,                    dc_options_set_uint16, "port",    required_argument, 'p', "PORT",          dc_uint16_from_string, "port",          dc_uint16_from_config, &default_port},
                    {(struct dc_setting *) settings->reuse_address,           dc_options_set_bool,   "force",   no_argument,       'f', "REUSE_ADDRESS", dc_flag_from_string,   "reuse_address", dc_flag_from_config,   &default_reuse},
            };
#pragma GCC diagnostic pop

    // note the trick here - we use calloc and add 1 to ensure the last line is all 0/NULL
    settings->opts.opts = dc_calloc(env, err, (sizeof(opts) / sizeof(struct options)) + 1, sizeof(struct options));
    dc_memcpy(env, settings->opts.opts, opts, sizeof(opts));
    settings->opts.flags = "c:vh:i:p:f";
    settings->opts.env_prefix = "DC_ECHO_";

    return (struct dc_application_settings *) settings;
}

static int destroy_settings(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err,
                            struct dc_application_settings **psettings) {
    struct application_settings *app_settings;

    DC_TRACE(env);
    app_settings = (struct application_settings *) *psettings;
    dc_setting_bool_destroy(env, &app_settings->verbose);
    dc_setting_string_destroy(env, &app_settings->hostname);
    dc_setting_regex_destroy(env, &app_settings->ip_version);
    dc_setting_uint16_destroy(env, &app_settings->port);
    dc_setting_bool_destroy(env, &app_settings->reuse_address);
    dc_free(env, app_settings->opts.opts, app_settings->opts.opts_size);
    dc_free(env, app_settings, sizeof(struct application_settings));

    if (env->null_free) {
        *psettings = NULL;
    }
    return 0;
}


static struct dc_server_lifecycle *create_server_lifecycle(const struct dc_posix_env *env, struct dc_error *err) {
    struct dc_server_lifecycle *lifecycle;

    DC_TRACE(env);
    lifecycle = dc_server_lifecycle_create(env, err);
    dc_server_lifecycle_set_create_settings(env, lifecycle, do_create_settings);
    dc_server_lifecycle_set_create_socket(env, lifecycle, do_create_socket);
    dc_server_lifecycle_set_set_sockopts(env, lifecycle, do_set_sockopts);
    dc_server_lifecycle_set_bind(env, lifecycle, do_bind);
    dc_server_lifecycle_set_listen(env, lifecycle, do_listen);
    dc_server_lifecycle_set_setup(env, lifecycle, do_setup);
    dc_server_lifecycle_set_accept(env, lifecycle, do_accept);
    dc_server_lifecycle_set_shutdown(env, lifecycle, do_shutdown);
    dc_server_lifecycle_set_destroy_settings(env, lifecycle, do_destroy_settings);

    return lifecycle;
}

static void destroy_server_lifecycle(const struct dc_posix_env *env, struct dc_server_lifecycle **plifecycle) {
    DC_TRACE(env);
    dc_server_lifecycle_destroy(env, plifecycle);
}


static int run(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err,
               struct dc_application_settings *settings) {
    int ret_val;
    struct dc_server_info *info;

    DC_TRACE(env);
    info = dc_server_info_create(env, err, "Echo Server", NULL, settings);

    if (dc_error_has_no_error(err)) {
        dc_server_run(env, err, info, create_server_lifecycle, destroy_server_lifecycle);
        dc_server_info_destroy(env, &info);
    }
    if (dc_error_has_no_error(err)) {
        ret_val = 0;
    } else {
        ret_val = -1;
    }
    return ret_val;
}


void signal_handler(__attribute__ ((unused)) int signnum) {
    printf("caught %d\n", signnum);
    exit_signal = 1;
}

static void do_create_settings(const struct dc_posix_env *env, struct dc_error *err, void *arg) {
    struct application_settings *app_settings;
    const char *ip_version;
    int family;

    DC_TRACE(env);
    app_settings = arg;
    ip_version = dc_setting_regex_get(env, app_settings->ip_version);

    if (dc_strcmp(env, ip_version, "IPv4") == 0) {
        family = PF_INET;
    } else {
        if (dc_strcmp(env, ip_version, "IPv6") == 0) {
            family = PF_INET6;
        } else {
            DC_ERROR_RAISE_USER(err, "Invalid ip_version", -1);
            family = 0;
        }
    }
    if (dc_error_has_no_error(err)) {
        const char *hostname;

        hostname = dc_setting_string_get(env, app_settings->hostname);
        dc_network_get_addresses(env, err, family, SOCK_STREAM, hostname, &app_settings->address);
    }
}

static void do_create_socket(const struct dc_posix_env *env, struct dc_error *err, void *arg) {
    struct application_settings *app_settings;
    int socket_fd;

    DC_TRACE(env);
    app_settings = arg;
    socket_fd = dc_network_create_socket(env, err, app_settings->address);

    if (dc_error_has_no_error(err)) {
        app_settings = arg;
        app_settings->server_socket_fd = socket_fd;
    } else {
        socket_fd = -1;
    }
}

static void do_set_sockopts(const struct dc_posix_env *env, struct dc_error *err, void *arg) {
    struct application_settings *app_settings;
    bool reuse_address;

    DC_TRACE(env);
    app_settings = arg;
    reuse_address = dc_setting_bool_get(env, app_settings->reuse_address);
    dc_network_opt_ip_so_reuse_addr(env, err, app_settings->server_socket_fd, reuse_address);
}

static void do_bind(const struct dc_posix_env *env, struct dc_error *err, void *arg) {
    struct application_settings *app_settings;
    uint16_t port;

    DC_TRACE(env);
    app_settings = arg;
    port = dc_setting_uint16_get(env, app_settings->port);

    dc_network_bind(env,
                    err,
                    app_settings->server_socket_fd,
                    app_settings->address->ai_addr,
                    port);
}

static void do_listen(const struct dc_posix_env *env, struct dc_error *err, void *arg) {
    struct application_settings *app_settings;
    int backlog;

    DC_TRACE(env);
    app_settings = arg;
    backlog = 5;    // TODO: make this a setting
    dc_network_listen(env, err, app_settings->server_socket_fd, backlog);
}

static void do_setup(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err,
                     __attribute__ ((unused)) void *arg) {
    DC_TRACE(env);
}

#define MAX 80
int fuel = 0;

void *TCP(void *arg) {
    int *connfd = (int *) arg;
    char buff[MAX];
    for (;;) {
        memset(buff, 0, MAX);
        read(*connfd, buff, sizeof(buff));
        printf("From client TCP: %s\n", buff);

        if (strncmp("exit", buff, 4) == 0) {
            printf("\nServer Exit...\n");
            write(*connfd, buff, sizeof(buff));
            fuel = 1;
            break;
        }
        write(*connfd, buff, sizeof(buff));
        sleep(1);
    }
    return NULL;
}


void *UDP(void *arg) {
    struct application_settings *app_settings;
    struct sockaddr_in servaddr, cliaddr;
    dc_posix_tracer tracer;
    struct dc_posix_env env;
    const char *hostname;
    char buffer[MAXLINE];
    in_port_t port;
    FILE *fp;
    int sockfd;

    app_settings = arg;

    tracer = NULL;
    dc_posix_env_init(&env, tracer);

    hostname = dc_setting_string_get(&env, app_settings->hostname);
    port = dc_setting_uint16_get(&env, app_settings->port);

    //printf("app_settings->address: %d\n", dc_network_create_socket(&env, err, app_settings->address));

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    inet_pton(AF_INET, hostname, &servaddr.sin_addr);
    servaddr.sin_port = htons(port);

    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *) &servaddr,
             sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    ssize_t len, n;

    len = sizeof(cliaddr);

    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);

    int flag = 0;
    while (fuel == 0) {
        n = recvfrom(sockfd, (char *) buffer, MAXLINE,
                     MSG_WAITALL, (struct sockaddr *) &cliaddr,
                     (socklen_t *) &len);
        if (n != -1) {
            if (flag == 0) {
                fp = fopen(inet_ntoa(cliaddr.sin_addr), "w");
                fprintf(fp, "%hu\n", app_settings->packet_number);
                flag = 1;
            }
            buffer[n] = '\0';
            // printf("Client : %s\n", buffer);
            fprintf(fp, "%s\n", buffer);
        }
    }

    // printf("IP address is: %s\n", inet_ntoa(cliaddr.sin_addr));
    //printf("port is: %d\n", (int) ntohs(cliaddr.sin_port));

    // sleep(2);
    printf("\nUDP Exit...\n");
    return NULL;
}

static bool do_accept(const struct dc_posix_env *env, struct dc_error *err, int *client_socket_fd, void *arg) {
    struct application_settings *app_settings;
    app_settings = (struct application_settings *) arg;

    bool ret_val;
    DC_TRACE(env);
    app_settings = arg;
    ret_val = false;
    int pid;

    uint16_t packet_Size;
    uint16_t starting_time;

    while (1) {
        printf("accepting\n");

        *client_socket_fd = dc_network_accept(env, err, app_settings->server_socket_fd);

        if (*client_socket_fd < 0) {
            exit(1);
        }
        printf("accepted\n");

        pid = fork();
        if (pid < 0) {
            perror("ERROR in new process creation");
            exit(1);
        }
        if (pid == 0) {
            close(app_settings->server_socket_fd);

            if (dc_error_has_error(err)) {
                if (exit_signal == 1 && dc_error_is_errno(err, EINTR)) {
                    ret_val = true;
                    dc_error_reset(err);
                }
            } else {
                char buff[1024];
                read(*client_socket_fd, buff, sizeof(buff));
                printf("From client TCP: %s\n", buff);
                write(*client_socket_fd, "ok", sizeof("ok"));

                char delim[] = " ";

                char *ptr = strtok(buff, delim);
                starting_time = (uint16_t) atoi(ptr);

                ptr = strtok(NULL, delim);
                packet_Size = (uint16_t) atoi(ptr);

                ptr = strtok(NULL, delim);
                app_settings->packet_number = (uint16_t) atoi(ptr);

                pthread_t thread_1, thread_2;

                if (pthread_create(&thread_1, NULL, &TCP, client_socket_fd) != 0) {
                    perror("Failed to create thread");
                }

                if (pthread_create(&thread_2, NULL, &UDP, arg) != 0) {
                    perror("Failed to create thread");
                }
                pthread_join(thread_1, NULL);
                pthread_join(thread_2, NULL);
            }
            exit(0);
        } else {
            //parent process
            // wait(NULL);
            close(*client_socket_fd);
        }
        sleep(2);
    }
    return ret_val;
}

static void do_shutdown(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err,
                        __attribute__ ((unused)) void *arg) {
    DC_TRACE(env);
}

static void
do_destroy_settings(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err, void *arg) {
    struct application_settings *app_settings;

    DC_TRACE(env);
    app_settings = arg;
    dc_freeaddrinfo(env, app_settings->address);
}
