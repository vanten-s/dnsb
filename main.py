
import socket
import logger

def create_query( name: str, query_type: int, query_class: int ):
    query = b'' # Initialize queries
    labels = name.split( "." ) # Get labels

    # Add labels to query
    for label in labels:
        query += len( label ).to_bytes( 1, 'little') # Add label length
        query += label.encode( ) # Add label

    query += b'\x00' # End label section

    # Add query type and query class
    query += query_type.to_bytes( 2, 'big' )
    query += query_class.to_bytes( 2, 'big' )

    return query

def generate_flags ( QR: int, OPCODE: int, AA: int, TC: int, RD: int, RA: int, Z: int, RCODE: int ):
    flags = 0

    flags = flags << 1 # Bitshift to make place for bit
    flags += QR # Add bit

    flags = flags << 4
    flags += OPCODE

    flags = flags << 1
    flags += AA

    flags = flags << 1
    flags += TC

    flags = flags << 1
    flags += RD

    flags = flags << 1
    flags += RA

    flags = flags << 3
    flags += Z

    flags = flags << 4
    flags += RCODE

    flag_bytes = flags.to_bytes( 2, 'big' ) # Convert to bytes

    return flag_bytes

# Create dns message for replying or similar
@logger.log
def create_dns_message( transaction_id, flags, number_of_questions, number_of_answers, number_of_authority_resource_records, number_of_additional_resource_records, query, answer=b'' ):
    message = b''

    message += transaction_id
    message += flags
    message += number_of_questions
    message += number_of_answers
    message += number_of_authority_resource_records
    message += number_of_additional_resource_records
    message += query
    message += answer

    return message

def parse_dns_message( message ):

    transaction_id = message[0:2  ]
    flags          = message[2:4  ]
    n_questions    = message[4:6  ]
    n_answers      = message[6:8  ]
    n_authrr       = message[8:10 ]
    n_addrr        = message[10:12]




