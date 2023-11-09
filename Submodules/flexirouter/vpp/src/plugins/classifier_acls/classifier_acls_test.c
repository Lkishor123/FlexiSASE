/*
 * Copyright (c) 2022 FlexiWAN
 *
 * List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *  - acl_based_classification: Feature to provide traffic classification using
 *  ACL plugin. Matching ACLs provide the service class and importance
 *  attribute. The classification result is marked in the packet and can be
 *  made use of in other functions like scheduling, policing, marking etc.
 *
 * This file is added by the Flexiwan feature: acl_based_classification.
 */
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <stdbool.h>

#define __plugin_msg_base classifier_acls_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <classifier_acls/classifier_acls.api_enum.h>
#include <classifier_acls/classifier_acls.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} classifier_acls_test_main_t;

classifier_acls_test_main_t classifier_acls_test_main;

static int api_classifier_acls_enable_disable (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  int enable_disable = 1;
  u32 sw_if_index = ~0;
  vl_api_classifier_acls_enable_disable_t * mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
          ;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
          ;
      else if (unformat (i, "disable"))
          enable_disable = 0;
      else
          break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name / explicit sw_if_index number \n");
      return -99;
    }

  /* Construct the API message */
  M(CLASSIFIER_ACLS_ENABLE_DISABLE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable_disable;

  /* send it... */
  S(mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}


/* NOT YET IMPLEMENTED */
static int api_classifier_acls_set_acls (vat_main_t * vam)
{
  return 0;
}

static int api_classifier_acls_set_interface (vat_main_t * vam)
{
  return 0;
}

/*
 * List of messages that the classifier_acls test plugin sends,
 * and that the data plane plugin processes
 */
#include <classifier_acls/classifier_acls.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
