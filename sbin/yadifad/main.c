/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2023, EURid vzw. All rights reserved.
 * The YADIFA TM software product is provided under the BSD 3-clause license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *        * Redistributions of source code must retain the above copyright
 *          notice, this list of conditions and the following disclaimer.
 *        * Redistributions in binary form must reproduce the above copyright
 *          notice, this list of conditions and the following disclaimer in the
 *          documentation and/or other materials provided with the distribution.
 *        * Neither the name of EURid nor the names of its contributors may be
 *          used to endorse or promote products derived from this software
 *          without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *------------------------------------------------------------------------------
 *
 */

/** @defgroup yadifad Yet Another DNS Implementation for all
 * 
 *  @brief Yet Another DNS Implementation for all
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#define _POSIX_SOURCES
#define __USE_POSIX

#include "server-config.h"

#include <sys/types.h>
#include <sys/time.h>
#ifndef WIN32
#include <sys/resource.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/fdtools.h>
#include <dnscore/parsing.h>
#include <dnscore/dnscore.h>
#include <dnscore/chroot.h>
#include <dnscore/async.h>
#include <dnscore/service.h>
#include <dnscore/logger-output-stream.h>
#include <dnscore/socket-server.h>

// #include <dnscore/dnskey_ecdsa.h>

#include <dnscore/pid.h>
#include <dnscore/server-setup.h>

#include <dnscore/sys_get_cpu_count.h>

#include <dnsdb/zdb.h>

#if ZDB_HAS_DNSSEC_SUPPORT
#include <dnsdb/dnssec.h>
#include <dnsdb/dnssec-keystore.h>
#endif

#include "server_error.h"
#include "config_error.h"
#include "signals.h"
#include "server.h"
#include "notify.h"


#include "database-service.h"

#if HAS_DYNUPDATE_SUPPORT
#include "dynupdate_query_service.h"
#endif

#if HAS_DYNCONF_SUPPORT
#include "dynconf.h"
#endif

#include "process_class_ch.h"

#include "zone-signature-policy.h"

#if HAS_EVENT_DYNAMIC_MODULE
#include "dynamic-module-handler.h"
#endif

#include "buildinfo.h"

#define MODULE_MSG_HANDLE g_server_logger

#define FUZZ_PERSISTENT_MODE

#ifdef FUZZ_PERSISTENT_MODE
__AFL_FUZZ_INIT();
#endif

/*------------------------------------------------------------------------------
 * GO */

static bool server_do_clean_exit = FALSE;
int g_yadifa_exitcode = EXIT_SUCCESS;
static bool own_pid = FALSE;

static bool main_config_log_from_start = FALSE;     // start logging asap
static u32  main_config_features = DNSCORE_ALL;     // start all services (can be reduced on early config)
static bool main_config_help_requested = FALSE;     // no point in starting anything

void config_logger_setdefault();
void config_logger_cleardefault();
int process_command_line(int argc, char **argv, config_data *config);
int zalloc_init();
void config_unregister_main();

static void
server_register_errors()
{
    error_register(CFG_ERROR_BASE,"CFG_ERROR_BASE");

    /* Config error codes */

    error_register(CONFIG_ZONE_ERR,"Error in config file");

    /*
    error_register(YDF_ERROR_BASE,"YDF_ERROR_BASE");
    error_register(YDF_ALREADY_RUNNING,"YDF_ALREADY_RUNNING");
    error_register(YDF_PID_PATH_IS_WRONG,"YDF_PID_PATH_IS_WRONG");
    */

    /* Main error codes */
    
    error_register(ZONE_LOAD_MASTER_TYPE_EXPECTED,"ZONE_LOAD_MASTER_TYPE_EXPECTED");
    error_register(ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED,"ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED");
    error_register(ZONE_LOAD_SLAVE_TYPE_EXPECTED,"ZONE_LOAD_SLAVE_TYPE_EXPECTED");
    error_register(ZRE_NO_VALID_FILE_FOUND,"ZRE_NO_VALID_FILE_FOUND");
    
    error_register(ANSWER_NOT_ACCEPTABLE,"ANSWER_NOT_ACCEPTABLE");
    error_register(ANSWER_UNEXPECTED_EOF,"ANSWER_UNEXPECTED_EOF");

    /* ACL */
    error_register(ACL_ERROR_BASE,"ACL_ERROR_BASE");
    error_register(ACL_TOKEN_SIZE_ERROR,"ACL_TOKEN_SIZE_ERROR");
    error_register(ACL_UNEXPECTED_NEGATION,"ACL_UNEXPECTED_NEGATION");
    error_register(ACL_WRONG_V4_MASK,"ACL_WRONG_V4_MASK");
    error_register(ACL_WRONG_V6_MASK,"ACL_WRONG_V6_MASK");
    error_register(ACL_WRONG_MASK,"ACL_WRONG_MASK");
    error_register(ACL_DUPLICATE_ENTRY,"ACL_DUPLICATE_ENTRY");
    error_register(ACL_RESERVED_KEYWORD,"ACL_RESERVED_KEYWORD");
    error_register(ACL_TOO_MANY_TOKENS,"ACL_TOO_MANY_TOKENS");
    error_register(ACL_NAME_PARSE_ERROR,"ACL_NAME_PARSE_ERROR");
    error_register(ACL_UNKNOWN_TSIG_KEY,"ACL_UNKNOWN_TSIG_KEY");
    error_register(ACL_UPDATE_REJECTED,"ACL_UPDATE_REJECTED");
    error_register(ACL_NOTIFY_REJECTED,"ACL_NOTIFY_REJECTED");
    error_register(ACL_UNDEFINED_TOKEN,"ACL_UNDEFINED_TOKEN");
    
    error_register(CONFIG_WRONG_SIG_TYPE, "CONFIG_WRONG_SIG_TYPE");
    error_register(CONFIG_WRONG_SIG_VALIDITY, "CONFIG_WRONG_SIG_VALIDITY");
    error_register(CONFIG_WRONG_SIG_REGEN, "CONFIG_WRONG_SIG_REGEN");
    
    error_register(DATABASE_ZONE_MISSING_DOMAIN, "DATABASE_ZONE_MISSING_DOMAIN");
    error_register(DATABASE_ZONE_MISSING_MASTER, "DATABASE_ZONE_MISSING_MASTER");
    error_register(DATABASE_ZONE_MISSING_TYPE, "DATABASE_ZONE_MISSING_TYPE");
    error_register(DATABASE_ZONE_CONFIG_DUP, "DATABASE_ZONE_CONFIG_DUP");
    
    error_register(NOTIFY_QUERY_TO_MASTER, "NOTIFY_QUERY_TO_MASTER");
    error_register(NOTIFY_QUERY_TO_UNKNOWN, "NOTIFY_QUERY_TO_UNKNOWN");
    error_register(NOTIFY_QUERY_FROM_UNKNOWN, "NOTIFY_QUERY_FROM_UNKNOWN");
    
    error_register(POLICY_ILLEGAL_DATE, "POLICY_ILLEGAL_DATE");
    error_register(POLICY_ILLEGAL_DATE_TYPE, "POLICY_ILLEGAL_DATE_TYPE");
    error_register(POLICY_ILLEGAL_DATE_PARAMETERS, "POLICY_ILLEGAL_DATE_PARAMETERS");
    error_register(POLICY_ILLEGAL_DATE_COMPARE, "POLICY_ILLEGAL_DATE_COMPARE");
    error_register(POLICY_UNDEFINED, "POLICY_UNDEFINED");
    error_register(POLICY_KEY_SUITE_UNDEFINED, "POLICY_KEY_SUITE_UNDEFINED");
    error_register(POLICY_NULL_REQUESTED, "POLICY_NULL_REQUESTED");
    error_register(POLICY_ZONE_NOT_READY, "POLICY_ZONE_NOT_READY");

}

static void
main_dump_info()
{
    log_info("starting YADIFA " VERSION);
    log_info("built with " BUILD_OPTIONS);
#if !DEBUG
    log_info("release build");
#else
    log_info("debug build");
#endif
    log_info("------------------------------------------------");
    log_info("YADIFA is maintained by EURid");
    log_info("Source code is available at http://www.yadifa.eu");
    log_info("------------------------------------------------");
    log_info("got %u CPUs", sys_get_cpu_count());
    log_info("using %u UDP listeners per interface", g_config->thread_count_by_address);
    log_info("accepting up to %u TCP queries", g_config->max_tcp_queries);
#if DNSCORE_HAS_ZALLOC_SUPPORT
    log_info("self-managed memory enabled"); // ZALLOC
#endif
}

static bool yadifad_config_on_section_loggers_read_done_once = FALSE;

static ya_result
yadifad_config_on_section_loggers_read(const char* name, int index)
{
    (void)name;
    (void)index;

    if(yadifad_config_on_section_loggers_read_done_once)
    {
        return SUCCESS;
    }

    //formatln("yadifad_config_on_section_main_read(%s,%i)", name, index);

    ya_result                                                   ret;
    pid_t                                                       pid;
    
    if(FAIL(ret = pid_check_running_program(g_config->pid_file, &pid)))
    {
        log_err("%s already running with pid: %lu (%s)", PROGRAM_NAME, pid, g_config->pid_file);
        return ret;
    }
    
    /*
     * From here we have the loggers ready (if any was set)
     */

    if(g_config->server_flags & SERVER_FL_DAEMON)
    {
        server_setup_daemon_go();
    }

    logger_start();
    
    if(!config_logger_isconfigured())
    {
        config_logger_setdefault();
    }
    else
    {
        config_logger_cleardefault();
    }
    
    main_dump_info();
    
    if(FAIL(ret = server_service_init()))
    {
        log_err("failed to initialise network service: %r", ret);
        return ret;
    }
    
    database_service_init();

    notify_service_init();

    /* Initialize signals used for inter process communication and
     * quitting the program
     */

    if(FAIL(ret = signal_handler_init()))
    {
        log_err("failed to setup the signal handler: %r", ret);

        if(!(g_config->server_flags & SERVER_FL_DAEMON))
        {
            osformatln(termerr, "error: failed to setup the signal handler: %r", ret);
            flusherr();
        }

        logger_flush();

        return ret;
    }

    notify_wait_servicing();
    
    signal_setup(); // hooks the signals

#if DEBUG
    println("yadifad_config_on_section_loggers_read done");
    flushout();
#endif

    yadifad_config_on_section_loggers_read_done_once = TRUE;

    return CONFIG_CALLBACK_RESULT_CONTINUE;
}


/**
 * Handles the configuration part of the server.
 * 
 * @param argc
 * @param argv
 * @return  0  if the configuration is successful and the server can start
 * @return  1 if no error occurred but the server must stop
 * @return -1 if an error occurred and the server must stop
 */

int
main_config(int argc, char *argv[])
{
    ya_result ret;
    
    if(main_config_log_from_start) // -L was used on the command line
    {
        config_logger_setdefault();
    }
    
    /*
     *  Initialise configuration file and set standard values
     */
    
    if(FAIL(ret = yadifad_config_init()))
    {
        osformatln(termerr, "error: setting up configuration: %r", ret);
        flusherr();

        return ret;
    }
    
    // channels then loggers
    config_add_on_section_read_callback("loggers", yadifad_config_on_section_loggers_read);
    
    if((ret = yadifad_config_cmdline(argc, argv)) != 0)
    {
        if(FAIL(ret))
        {
            return ret;
        }
        
        return 1;
    }

    if(FAIL(ret = yadifad_config_read(g_config->config_file)))
    {
        osformatln(termerr, "error: reading configuration: %r", ret);
        flusherr();

        return ret;
    }
    
    if(FAIL(ret = yadifad_config_finalize()))
    {
        osformatln(termerr, "error: processing configuration: %r", ret);
        flusherr();

        return ret;
    }
        
#if 0 && DEBUG
    config_print(termout);    
    osformatln(termout, "starting logging service");
#endif
    
    /*
     * flushes whatever is in the buffers
     */

    flushout();
    flusherr();
    
    return 0;
}

/**
 * Tries to create a temporary file in a directory.
 * Deletes the file afterward.
 * 
 * @param dir
 * @return true iff the file was created
 */

static bool
main_final_tests_is_directory_writable(const char* dir)
{
    ya_result ret;
    if(FAIL(ret = access_check(dir, ACCESS_CHECK_READWRITE)))
    {
        ttylog_err("error: '%s' is not writable as (%d:%d): %r", dir, getuid(), getgid(), ret);
        return FALSE;
    }

    return TRUE;    
}

/**
 * last tests before the real startup (directory writable)
 */

static ya_result
main_final_tests()
{
    if(!main_final_tests_is_directory_writable(g_config->data_path))
    {
        return DIRECTORY_NOT_WRITABLE;
    }
    if(!main_final_tests_is_directory_writable(g_config->keys_path))
    {
        return DIRECTORY_NOT_WRITABLE;
    }

    if((g_config->server_flags & SERVER_FL_LOG_FILE_DISABLED) == 0)
    {
        if(!main_final_tests_is_directory_writable(g_config->log_path))
        {
            return DIRECTORY_NOT_WRITABLE;
        }
    }
    if(!main_final_tests_is_directory_writable(g_config->xfr_path))
    {
        return DIRECTORY_NOT_WRITABLE;
    }
    
    return SUCCESS;
}

/** \brief Function executed by atexit
 *
 * The atexit() function registers the given function to be called at normal
 * process termination, either via exit(?) or via return from the program
 * main(). Functions so registered are called in the reverse order of their
 * registration; no arguments are passed.
 */

static void
main_exit()
{
    if(own_pid)
    {
        log_info("shutting down");
    }
    
    server_service_stop();
    
    server_service_finalize();
    
#if HAS_DYNUPDATE_SUPPORT
    dynupdate_query_service_stop();
#endif
    
    notify_service_stop();
    
#if HAS_EVENT_DYNAMIC_MODULE
    dynamic_module_handler_finalize();
#endif
    
    signal_handler_finalize();
    notify_service_finalize();
    database_service_finalize();

#if DNSCORE_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
    dnssec_policy_finalize();
#endif
    class_ch_set_hostname(NULL);    
    class_ch_set_id_server(NULL);
    class_ch_set_version(NULL);

#if DNSCORE_HAS_NSID_SUPPORT
    edns0_set_nsid(NULL, 0);
#endif
    
    logger_flush();
        
    flushout();
    flusherr();

    if(server_do_clean_exit)
    {
        log_info("stopping database");

        database_shutdown(g_config->database);

        if(own_pid)
        {
            log_info("releasing pid file lock");

            pid_file_destroy(g_config->pid_file);
        }
        
        //config_unregister_main();

        logger_flush();

        flushout();
        flusherr();

#if DNSCORE_HAS_ACL_SUPPORT
        acl_definitions_free();
#endif
        dnscore_finalize();
    }
    else
    {
        if(own_pid)
        {
            log_info("releasing pid file lock");

            pid_file_destroy(g_config->pid_file);
        }

        logger_flush();

        flushout();
        flusherr();
    }
}

/** \brief Main function of yadifa
 *
 *  @param[in] argc number of arguments on the command line
 *  @param[in] argv array of arguments on the command line
 *
 *  @return EXIT_SUCCESS
 *  @return EXIT_FAILURE
 *  @return exit codes
 *
 *
 */



/**
 * This will stop YADIFAD if the libraries have been build-configured differently or made differently.
 * 
 * The most typical trigger is "make debug" vs "make", is, because it has not been followed by,
 * respectively, a "make debug-install" or a "make install"
 * 
 * Or, in the case of a static build, a mix code versions that would have required a "make clean"
 * 
 */

static void
main_check_build_settings()
{
    if(dnscore_getfingerprint() != dnscore_getmyfingerprint())
    {
        printf("yadifad: the linked dnscore features are %08x but the lib has been compiled against one with %08x", dnscore_getfingerprint(), dnscore_getmyfingerprint());
        fflush(NULL);
        abort(); // binary incompatiblity : full stop
    }
    
    if(dnsdb_getfingerprint() != dnsdb_getmyfingerprint())
    {
        printf("yadifad: the linked dnsdb features are %08x but the lib has been compiled against one with %08x", dnsdb_getfingerprint(), dnsdb_getmyfingerprint());
        fflush(NULL);
        abort(); // binary incompatiblity : full stop
    }
}

/**
 * The flag must be checked this way as the internal command line/configuration parsing mechanism
 * would miss the start.
 * 
 * @param argc
 * @param argv
 */

static int
main_early_argv_check(int argc, char *argv[])
{
    int ret = 0;
    
    for(int i = 1; i < argc; ++i)
    {
        if(strcmp(argv[i], "-L") == 0)
        {
            main_config_log_from_start = TRUE;
        }
        if(strcmp(argv[i], "-h") == 0)
        {
            main_config_help_requested = TRUE;
            main_config_features = DNSCORE_TINYRUN;
            ++ret;
        }
        else if(strcmp(argv[i], "--help") == 0)
        {
            main_config_help_requested = TRUE;
            main_config_features = DNSCORE_TINYRUN;
            ++ret;
        }
        else if(strcmp(argv[i], "-V") == 0)
        {
            main_config_features = DNSCORE_TINYRUN;
        }
        else if(strcmp(argv[i], "--version") == 0)
        {
            main_config_features = DNSCORE_TINYRUN;
        }
    }
    
    return ret;
}

static void
main_ignore_signals_while_starting_up()
{
    static const int ignore_these[] = {SIGHUP, SIGUSR1, SIGINT, SIGTERM, SIGPIPE, 0};

    for(int i = 0; ignore_these[i] != 0; ++i)
    {
        signal(ignore_these[i], SIG_IGN);
    }
}

//AFL FUZZ LOOP IN SEPERATE THREAD

#ifdef FUZZ_PERSISTENT_MODE

void afl_fuzz_loop(/*const char* server_ip, int server_port*/)
{
    #ifdef __AFL_FUZZ_TESTCASE_LEN
        const char* server_ip = "127.0.0.1";
        int server_port = 53;

        struct sockaddr_in server_addr_proto;
        struct sockaddr_in server_addr;

        memset(&server_addr_proto, 0, sizeof(server_addr_proto));
        server_addr_proto.sin_family = AF_INET;
        server_addr_proto.sin_port = htons(server_port);
        inet_pton(AF_INET, server_ip, &(server_addr_proto.sin_addr));

        const char* known_response_data = "\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0a\x73\x6f\x6d\x65\x64\x6f\x6d\x61\x69\x6e\x02\x65\x75\x00\x00\x01\x00\x01x";
        unsigned char recv_buf[512];
        
        sleep(5);

        __AFL_INIT();

        unsigned char* fuzz_buf = __AFL_FUZZ_TESTCASE_BUF;

        while(__AFL_LOOP(1000))
        {
            
            memcpy(&server_addr, &server_addr_proto, sizeof(server_addr));

            int fuzz_len = __AFL_FUZZ_TESTCASE_LEN;

            #ifdef FUZZ_UDP_MODE

            //create the socket
            int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (sockfd < 0)
            {
                log_err("Could not create fuzz socket. Exiting Thread.");
                break;
            }
            
            //send the fuzz buffer
            
            if (sendto(sockfd, fuzz_buf, fuzz_len, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
            {
                log_err("Failed to send fuzz_buf, god help us.");
                continue;
            }

                //send data we know evokes a response
            if (sendto(sockfd, known_response_data, 31, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
            {
                log_err("Failed to send known data, god help us.");
                continue;
            }

            //see if we received a response
            int bytes_recvd = 0;
            int server_struct_length = 0;

            bytes_recvd = recvfrom(sockfd, recv_buf, 512, 0, (struct sockaddr*)&server_addr, &server_struct_length);
            
            close(sockfd);

            #else

            int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sockfd < 0)
            {
                log_err("Could not create fuzz socket. Exiting Thread.");
                break;
            }

            if (connect(sockfd, &server_addr, sizeof(server_addr)) < 0)
            {
                log_err("Could not connect fuzz socket. Exiting Thread.");
                continue;
            }

            if (send(sockfd, fuzz_buf, fuzz_len, NULL) < 0)
            {
                log_err("Could not send fuzz_buf, god help us.");
                continue;
            }

            shutdown(sockfd, SHUT_RDWR);
            close(sockfd);
            sockfd = -1;
            usleep_ex(250);

            sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sockfd < 0)
            {
                log_err("Could not create test socket. Exiting Thread.");
                continue;
            }

            if (connect(sockfd, &server_addr, sizeof(server_addr)) < 0)
            {
                log_err("Could not connect test socket. simulating timeout.");
                for(;;)
                {
                    sockfd++;
                }
            }

            if (send(sockfd, known_response_data, 31, NULL) < 0)
            {
                log_err("Could not send known response data, simulating timeout.");
                for(;;)
                {
                    sockfd++;
                }
            }

            int bytes_recvd = 0;

            bytes_recvd = recv(sockfd, recv_buf, 512, NULL);

            close(sockfd);

            #endif
        }

        //kill(getpid(), SIGKILL);
        quick_exit(0);
    #endif
    
    log_err("FUZZ loop did not compile, check compiler used, FUZZ thread exiting.");
    return;
}

#else

void afl_fuzz_loop(/*const char* server_ip, int server_port*/)
{
    sleep(5);

    const char* server_ip = "127.0.0.1";
    int server_port = 53;

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0)
    {
        log_err("Could not create fuzz socket.");
        quick_exit(0);
    }    

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &(server_addr.sin_addr));

    unsigned char* fuzz_buf[80000];
    unsigned char recv_buf[512];

    const char* known_response_data = "\xa5\xb5\xd1\xa7\x2e\xa0\x09\x71\xee\xf2\x4a\xa0\x44\x97\x23\x17\x2f\x7a\xe1\x2d\xa6\x0b\xa9\x87\xba\x67\xcd\xbd\x7d\x04\xee\xe5\xb9\x1f\x52\x66\x5f\xff\x84\x77\x74\xf7\x13\x83\xfe\x86\x74\x7d\x3f\xbe\xea\x2e\x70\x2a\xf1\x4b\x7a\x71\x35\xf1\x53\x4a\x26\xe2\xfe\x58\xc4\x1d\x2d\xe5\x2a\xb1\x8c\xde\xd8\xbf\x9a\x88\x6c\x1b\x16\x23\x3f\x98\xcd\x7f\x78\x40\x3d\x31\x91\x48\x49\x5c\xf7\x26\x45\x38\xc7\x7d\x76\x4a\xae\x01\x10\x9c\xd5\xa5\x59\x43\x87\x2c\x48\x5a\x52\xe3\xca\xfe\x46\xe3\x76\x06\xfd\xe2\x28\xf5\xd8\x19\x39\x8b\xec\x7d\x62\xa5\xc8\x15\xa1\xc2\xe3\xbc\x8a\xb5\x9c\x6e\xd8\xa9\x6c\x76\xa1\x31\xee\x46\x91\x69\x8c\x62\xfb\xd2\x62\x26\x8f\x21\xcc\x85\x94\x38\xbd\x3a\xc0\x52\x48\xce\x17\x35\x04\x74\xae\xaa\x22\x88\x37\x60\x0d\x7b\xb0\x9a\x3d\x80\xfe\x27\xf8\x84\xd9\xc3\x82\xec\xc7\x8d\x06\x0d\x17\x58\xca\x25\xc5\xce\xd8\x56\x91\xd9\x72\x7b\xaf\x79\x4e\xf2\xf3\x8c\xd7\x88\x14\x1a\xbf\x8c\x00\x59\xb1\x12\x40\x33\xbb\xfa\x53\x8a\x07\xf5\x11\x0f\x0d\x67\x81\x6f\x44\xc5\x6e\xf9\x02\xd8\x81\xb5\x00\xfa\x64\x5a\xf6\x79\xbc\xc1\x19\xa7\x49\x96\xa6\x90\x9f\x10\x51\xb4\x93\x83\x47\x50\x38\xe4\xb0\x27\x36\x94\xf0\x2d\xc4\x43\xd1\x4d\x9d\x59\x76\x82\x21\x5d\x29\xd3\xcc\xa9\x73\x55\xf1\x40\xfa\xdc\x43\x93\xe9\x6c\x31\xc5\x47\x6c\x30\xec\x3e\x4a\x7d\xa8\xcf\x48\x19\xd0\x94\x58\xb7\x45\xa9\x5c\x62\xff\x1c\x7d\x59\x0b\xc3\x0e\xd9\x3d\xc0\x35\x1c\xd2\xb3\x80\x69\x32\x8d\xe2\xba\x64\x68\x0f\x6b\xf2\xa2\xec\xd4\xb9\x81\x6a\xc0\x49\x1f\xe8\x9b\xbd\xc9\xa7\x50\xfa\x5c\xf2\xe5\x66\xa3\xf2\x1d\xb2\x31\x46\xe6\x52\x4a\xe8\x84\x37\xe5\x81\x40\x59\xe6\xaa\xdb\x86\xf7\xa1\x44\x3a\xd0\x6d\x7f\x20\x13\x23\xa0\x0c\xeb\xf0\x31\x64\xab\xbd\x3d\x58\x68\x94\xc9\x34\xe1\x69\xf0\xb3\xd4\x2a\xf6\x7b\xb7\x67\x18\x58\x73\x51\x10\x63\x98\x1a\xa6\xc5\x61\xe7\x83\x60\xec\xb4\x6f\xdb\x07\xd0\x54\xaf\xbe\x16\x79\xbb\x64\x44\x6c\xe8\xd7\x45\x77\x49\x6a\x66\x74\x3d\x5b\xaa\xf8\xf1\x87\x49\xf4\x0e\x59\x9e\x02\xf3\xe2\xb1\xd3\x6f\x6a\x3a\xbf\x09\x78\xa3\x2f\x56\xa7\x6c\xeb\xb5\xfb\xfc\x0a\x67\x2d\xb5\x0b\xd6\xbc\x68\x71\x0b\x20\xc4\xbe\x0f\xf8\xe8\x5e\x48\x16\x06x";

    //Deferred initialization
    __AFL_INIT();

    //send the fuzz buffer
    int fuzz_len = read(0, fuzz_buf, 80000);

    if (fuzz_len <= 0)
    {
        log_err("Failed to read from stdin.");
        quick_exit(0);
    }
    
    //send the fuzz data
    if (sendto(sockfd, fuzz_buf, fuzz_len, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        log_err("Failed to send fuzz_buf, god help us.");
        quick_exit(0);
    }

    //send data we know evokes a response
    if (sendto(sockfd, known_response_data, 512, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        log_err("Failed to send known data, god help us.");
        quick_exit(0);
    }

    //clear the recv buffer
    int bytes_recvd = 0;
    int server_struct_length = 0;
    bytes_recvd = recvfrom(sockfd, recv_buf, 512, 0, (struct sockaddr*)&server_addr, &server_struct_length);
    //usleep_ex(3000);

    close(sockfd);
    //kill(getpid(), SIGKILL);
    quick_exit(0);
}
#endif

int
main(int argc, char *argv[])
{
    ya_result ret;
    


    /**
     *  Initialises the core library:
     * _ checks basic architecture settings (endianness, types sizes, random generator, ...)
     * _ initialises dns types and classes name<->id matching
     * _ initialises text formatting (format*, log*)
     * _ initialises standard output streams
     * _ initialises the logger
     * _ registers core error codes
     * _ registers TSIG algorithms
     * _ registers an exit function
     * _ resets and start the alarm/timer function
     */
    
#if DEBUG
    puts("YADIFA debug build");
#if HAS_RRL_SUPPORT
    puts("RRL support: yes");
#else
    puts("RRL support: no");
#endif
#endif
    
    main_check_build_settings();
    
    if(main_early_argv_check(argc, argv) != 0)
    {
        // print the help using printf & flush

        dnscore_init_ex(DNSCORE_TINYRUN, argc, argv);
        yadifad_print_usage(argv[0]);

        return 1;
    }

    main_ignore_signals_while_starting_up();

    dnscore_init_ex(main_config_features, argc, argv);

    //main_check_log_from_start(argc, (const char**)argv);
        
    async_message_pool_init();

    // registers yadifad error codes

    server_register_errors();
    
    // arms the exit handling function
    
#if HAS_EVENT_DYNAMIC_MODULE
    dynamic_module_handler_init();
#endif

    atexit(main_exit);
    
    // ?
    // register all the services:
    // server, database, ...
    
#if HAS_DYNCONF_SUPPORT
    //dynconf_service_init();
    //dynconf_service_start();
#endif    
    // configures, exit if ordered to (version/help or error)
    //
    
    if((ret = main_config(argc, argv)) != SUCCESS)
    {
        return ISOK(ret)?EXIT_SUCCESS:EXIT_CONFIG_ERROR;
    }

    // This is always 'exit' on failure
    pid_t pid;
    if(FAIL(ret = pid_check_running_program(g_config->pid_file, &pid)))
    {
        log_err("%s already running with pid: %lu (%s)", PROGRAM_NAME, pid, g_config->pid_file);
        return EXIT_FAILURE; // don't use ret
    }

    /*
     * We are really starting up. After this we may want to do a clean exit.
     */

    server_do_clean_exit = TRUE;

    /*
     * Setup the necessary environmental changes: core limits, root change, id change, and creation of pid file
     */

    u32 setup_flags = SETUP_CORE_LIMITS | SETUP_ID_CHANGE | SETUP_CREATE_PID_FILE;

    if(g_config->server_flags & SERVER_FL_CHROOT)
    {
        setup_flags |= SETUP_ROOT_CHANGE;
    }

#ifndef WIN32
    {
        if(g_config->set_nofile >= 0)
        {
            struct rlimit nofile_limits = {0, 0};

            if(g_config->set_nofile == 0)
            {
                int tcp = g_config->max_tcp_queries;
                int addresses = host_address_count(g_config->listen);
                int workers_by_addresses = g_config->thread_count_by_address;

                int nofile = tcp * 2 + addresses * workers_by_addresses + 1024;

                nofile_limits.rlim_cur = nofile;
                nofile_limits.rlim_max = nofile;
            }
            else
            {
                nofile_limits.rlim_cur = g_config->set_nofile;
                nofile_limits.rlim_max = g_config->set_nofile;
            }

            ttylog_notice("setting file open limits to %i", nofile_limits.rlim_cur);

            if(setrlimit(RLIMIT_NOFILE, &nofile_limits) < 0)
            {
                ttylog_err("failed to set file open limits to %i : %r", nofile_limits.rlim_cur, ERRNO_ERROR);
            }
        }

        struct rlimit limits;
        getrlimit(RLIMIT_NOFILE, &limits);

        if(limits.rlim_cur < 1024)
        {
            ttylog_err("file open limits are too small (%i < 1024) to even try to go on.", limits.rlim_cur);
            return EXIT_FAILURE;
        }

        if(limits.rlim_cur < 65536)
        {
            ttylog_notice("file open limits could be higher (%i < 65536).  The highest the better.", limits.rlim_cur);
        }
    }
#endif

    if(FAIL(ret = server_setup_env(&g_config->pid, &g_config->pid_file, g_config->uid, g_config->gid, setup_flags)))
    {
        log_err("server setup failed: %r", ret);
        return EXIT_FAILURE;
    }
    
    own_pid = TRUE;
    
#if ZDB_HAS_DNSSEC_SUPPORT
    dnssec_keystore_setpath(g_config->keys_path);
#endif
    logger_reopen();

    /// last tests before the real startup (directory writable)
    
    if(FAIL(main_final_tests()))
    {
        return EXIT_FAILURE;
    }

    // database service
    //
    // needs about nobody

    log_info("loading zones");
    
    if(FAIL(ret = database_startup(&g_config->database)))
    {
        log_err("loading zones: %r", ret);

        return EXIT_FAILURE;
    }
    
    /*
     * Starts the services, ending with the server.
     * Waits for the shutdown signal.
     */
    
    int exit_code = EXIT_SUCCESS;

#if HAS_EVENT_DYNAMIC_MODULE
    dynamic_module_startup();
#endif

    while(!dnscore_shuttingdown())
    {
        log_info("starting notify service");

        notify_service_start();

#if HAS_DYNUPDATE_SUPPORT

        log_info("starting dynupdate service");

        // dynupdate service
        //
        // called by the dns server
        // uses the database

        dynupdate_query_service_init();
        dynupdate_query_service_start();
#endif
/*
        if(ctrl_has_dedicated_listen())
        {
            // start ctrl server on its address(es) that does not match the DNS server addresses
        }
*/      
        log_info("starting fuzz thread");

        thread_t fuzz_thread;
        thread_create(&fuzz_thread, afl_fuzz_loop, NULL);

        log_info("starting server");

        if(ISOK(ret = server_service_start_and_wait()))
        {
            exit_code = EXIT_SUCCESS;
        }
        else
        {
            exit_code = EXIT_FAILURE;
        }

#if HAS_DYNUPDATE_SUPPORT
        log_info("stopping dynupdate service");

        dynupdate_query_service_stop();
        dynupdate_query_service_finalise();

        log_info("dynupdate service stopped");
#endif

        log_info("stopping notify service");

        notify_service_stop();

        if(!dnscore_shuttingdown())
        {
            // server stop
           // server context stop
           server_context_stop();
           // server context start
           if(ISOK(ret = server_context_create()))
           {
               // server start
           }
           else
           {
               log_try_err("failed to start server: %r", ret);
           }
        }
    }

#if HAS_EVENT_DYNAMIC_MODULE
    dynamic_module_shutdown();
#endif
    
    /// @note DO NOT: logger_finalize() don't, it will be done automatically at exit

    return exit_code;
}

/** @} */
