%module pypst

// rename due to name clashes
%rename(from_offset) from;
%rename(to_offset) to;

// convert FILETIME to unixtime (int)
%typemap(out) FILETIME * {
	if($1 == NULL) {
		Py_INCREF(Py_None);
		$result =  Py_None;
	}
	else
		$result = PyInt_FromLong(fileTimeToUnixTime($1, 0));
}

%{
#include "libpst.h"
#include "timeconv.h"
#include "Python.h"

PyObject *pst_item_attach_data_as_pystring(pst_file *pstfile, pst_item_attach *attach) {
	PyObject *ret;
	if(attach->data == NULL) {	
		int size = 0;
		unsigned char *buff = NULL;
		size = pst_attach_to_mem(pstfile, attach, &buff);
		ret = PyString_FromStringAndSize(buff, size);
		if(buff != NULL)
			free(buff);
	}
	else {
		ret = PyString_FromStringAndSize(attach->data, attach->size);
	}
	return ret;
}

%}

// change to simple types which get mapped
typedef int int32_t;
typedef unsigned int u_int32_t;
typedef int time_t;

//%include "libpst.h"

#define PST_TYPE_NOTE 1
#define PST_TYPE_APPOINTMENT 8
#define PST_TYPE_CONTACT 9
#define PST_TYPE_JOURNAL 10
#define PST_TYPE_STICKYNOTE 11
#define PST_TYPE_TASK 12
#define PST_TYPE_OTHER 13
#define PST_TYPE_REPORT 14

typedef struct _pst_item_email_subject {
  int32_t off1;
  int32_t off2;
  char *subj;
} pst_item_email_subject;

typedef struct _pst_item_email {
  FILETIME *arrival_date;
  int32_t autoforward; // 1 = true, 0 = not set, -1 = false
  char *body;
  char *cc_address;
  char *common_name;
  int32_t  conv_index;
  int32_t  conversion_prohib;
  int32_t  delete_after_submit; // 1 = true, 0 = false
  int32_t  delivery_report; // 1 = true, 0 = false
  char *encrypted_body;
  int32_t  encrypted_body_size;
  char *encrypted_htmlbody;
  int32_t encrypted_htmlbody_size;
  int32_t  flag;
  char *header;
  char *htmlbody;
  int32_t  importance;
  char *in_reply_to;
  int32_t  message_cc_me; // 1 = true, 0 = false
  int32_t  message_recip_me; // 1 = true, 0 = false
  int32_t  message_to_me; // 1 = true, 0 = false
  char *messageid;
  int32_t  orig_sensitivity;
  char *outlook_recipient;
  char *outlook_recipient2;
  char *outlook_sender;
  char *outlook_sender_name;
  char *outlook_sender2;
  int32_t  priority;
  char *proc_subject;
  int32_t  read_receipt;
  char *recip_access;
  char *recip_address;
  char *recip2_access;
  char *recip2_address;
  int32_t  reply_requested;
  char *reply_to;
  char *return_path_address;
  int32_t  rtf_body_char_count;
  int32_t  rtf_body_crc;
  char *rtf_body_tag;
  char *rtf_compressed;
  int32_t  rtf_in_sync; // 1 = true, 0 = doesn't exist, -1 = false
  int32_t  rtf_ws_prefix_count;
  int32_t  rtf_ws_trailing_count;
  char *sender_access;
  char *sender_address;
  char *sender2_access;
  char *sender2_address;
  int32_t  sensitivity;
  FILETIME *sent_date;
  pst_entryid *sentmail_folder;
  char *sentto_address;
  pst_item_email_subject *subject;
} pst_item_email;

typedef struct _pst_item_contact {
  char *access_method;
  char *account_name;
  char *address1;
  char *address1_desc;
  char *address1_transport;
  char *address2;
  char *address2_desc;
  char *address2_transport;
  char *address3;
  char *address3_desc;
  char *address3_transport;
  char *assistant_name;
  char *assistant_phone;
  char *billing_information;
  FILETIME *birthday;
  char *business_address;
  char *business_city;
  char *business_country;
  char *business_fax;
  char *business_homepage;
  char *business_phone;
  char *business_phone2;
  char *business_po_box;
  char *business_postal_code;
  char *business_state;
  char *business_street;
  char *callback_phone;
  char *car_phone;
  char *company_main_phone;
  char *company_name;
  char *computer_name;
  char *customer_id;
  char *def_postal_address;
  char *department;
  char *display_name_prefix;
  char *first_name;
  char *followup;
  char *free_busy_address;
  char *ftp_site;
  char *fullname;
  int32_t  gender;
  char *gov_id;
  char *hobbies;
  char *home_address;
  char *home_city;
  char *home_country;
  char *home_fax;
  char *home_phone;
  char *home_phone2;
  char *home_po_box;
  char *home_postal_code;
  char *home_state;
  char *home_street;
  char *initials;
  char *isdn_phone;
  char *job_title;
  char *keyword;
  char *language;
  char *location;
  int32_t  mail_permission;
  char *manager_name;
  char *middle_name;
  char *mileage;
  char *mobile_phone;
  char *nickname;
  char *office_loc;
  char *org_id;
  char *other_address;
  char *other_city;
  char *other_country;
  char *other_phone;
  char *other_po_box;
  char *other_postal_code;
  char *other_state;
  char *other_street;
  char *pager_phone;
  char *personal_homepage;
  char *pref_name;
  char *primary_fax;
  char *primary_phone;
  char *profession;
  char *radio_phone;
  int32_t  rich_text;
  char *spouse_name;
  char *suffix;
  char *surname;
  char *telex;
  char *transmittable_display_name;
  char *ttytdd_phone;
  FILETIME *wedding_anniversary;
} pst_item_contact;

typedef struct _pst_item_attach {
  char *filename1;
  char *filename2;
  char *mimetype;
  char *data;
  size_t  size;
  int32_t  id2_val;
  int32_t  id_val; // calculated from id2_val during creation of record
  int32_t  method;
  int32_t  position;
  int32_t  sequence;
  struct _pst_item_attach *next;
} pst_item_attach;

typedef struct _pst_item_journal {
  FILETIME *end;
  FILETIME *start;
  char *type;
} pst_item_journal;

typedef struct _pst_item_appointment {
  FILETIME *end;
  char *location;
  FILETIME *reminder;
  FILETIME *start;
  char *timezonestring;
  int32_t showas;
  int32_t label;
} pst_item_appointment;

typedef struct _pst_desc_tree {
  u_int32_t id;
  pst_index_ll * list_index;
  pst_index_ll * desc;
  int32_t no_child;
  struct _pst_desc_tree * prev;
  struct _pst_desc_tree * next;
  struct _pst_desc_tree * parent;
  struct _pst_desc_tree * child;
  struct _pst_desc_tree * child_tail;
} pst_desc_ll;

typedef struct _pst_file {
  pst_index_ll *i_head, *i_tail;
  pst_index2_ll *i2_head;
  pst_desc_ll *d_head, *d_tail;
  pst_x_attrib_ll *x_head;
  int32_t index1;
  int32_t index1_count;
  int32_t index2;
  int32_t index2_count;
  FILE * fp;
  size_t size;
  unsigned char index1_depth;
  unsigned char index2_depth;
  unsigned char encryption;
  unsigned char id_depth_ok;
  unsigned char desc_depth_ok;
  unsigned char ind_type;
} pst_file;

typedef struct _pst_item {
  struct _pst_item_email *email; // data reffering to email
  struct _pst_item_folder *folder; // data reffering to folder
  struct _pst_item_contact *contact; // data reffering to contact
  struct _pst_item_attach *attach; // linked list of attachments
  struct _pst_item_attach *current_attach; // pointer to current attachment
  struct _pst_item_message_store * message_store; // data referring to the message store
  struct _pst_item_extra_field *extra_fields; // linked list of extra headers and such
  struct _pst_item_journal *journal; // data reffering to a journal entry
  struct _pst_item_appointment *appointment; // data reffering to a calendar entry
  int32_t type;
  char *ascii_type;
  char *file_as;
  char *comment;
  int32_t  message_size;
  char *outlook_version;
  char *record_key; // probably 16 bytes long.
  size_t record_key_size;
  int32_t  response_requested;
  FILETIME *create_date;
  FILETIME *modify_date;
  int32_t private;
} pst_item;

typedef struct _pst_item_folder {
  int32_t  email_count;
  int32_t  unseen_email_count;
  int32_t  assoc_count;
  char subfolder;
} pst_item_folder;

%extend pst_file {
	pst_file() {
		return (pst_file *) malloc(sizeof(pst_file));
	}
	~pst_file() {
		free(self);
	}
	int open(char *fname) {
		return pst_open(self, fname, "r");
	}
	int close() {
		return pst_close(self);
	}
	int load_index() {
		return pst_load_index(self);
	}
	int load_extended_attributes() {
		return pst_load_extended_attributes(self);
	}
	pst_item *get_item(pst_desc_ll *d_ptr) {
		return _pst_parse_item(self, d_ptr);
	}
	pst_desc_ll *getTopOfFolders(pst_item *item) {
		return pst_getTopOfFolders(self, item);
	}
	pst_desc_ll *get_ptr(u_int32_t id) {
		return _pst_getDptr(self, id);
	}
	PyObject *get_attach_data(pst_item_attach *attach) {
		return pst_item_attach_data_as_pystring(self, attach);
	}
}

void _pst_freeItem(pst_item *item);

/* time stuff from timeconv */
//time_t fileTimeToUnixTime( const FILETIME *filetime, DWORD *remainder );
//char * fileTimeToAscii (const FILETIME *filetime);
//struct tm * fileTimeToStructTM (const FILETIME *filetime);
