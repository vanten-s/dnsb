
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

# Parse query
def parse_query( query: bytes ):
    # Get labels
    labels = [ ]
    while True:
        length = query[ 0 ]
        labels.append( query[ 1:length+1 ].decode( 'utf-8' ) )
        query = query[ length+1: ]
        if query[ 0 ] == 0:
            query = query[ 1: ]
            break

    domain = '.'.join( labels )

    query_type = int.from_bytes( query[ :2 ], 'big' )
    query_class = int.from_bytes( query[ 2:4 ], 'big' )

    return domain, query_type, query_class

# Create answer
def create_answer( offset: int, answer_type: int, answer_class: int, ttl: int, answer_data: bytes ):
    answer = b'\xc0'
    answer += offset.to_bytes( 1, 'big' )
    answer += answer_type.to_bytes( 2, 'big' )
    answer += answer_class.to_bytes( 2, 'big' )
    answer += ttl.to_bytes( 4, 'big' )
    answer += len( answer_data ).to_bytes( 2, 'big' )
    answer += answer_data

    return answer

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

# Parse dns message
def parse_dns_message( message: bytes ):
    # Sepearate static length fields

    transaction_id      = message[ 0:2 ]
    flags               = message[ 2:4 ]
    n_questions         = message[ 4:6 ]
    n_answers           = message[ 6:8 ]
    n_authrr            = message[ 8:10]
    n_addrr             = message[10:12]
    queries_and_answers = message[12:  ]

    # Put individual queries in an array
    queries = [ ]
    query_index = 0
    for i in range( 0, int.from_bytes( n_questions, 'big' ) ):
        end_of_current_query = queries_and_answers[ query_index: ].index( b'\x00' ) + 4
        queries.append( queries_and_answers[ query_index:end_of_current_query + query_index + 1 ] )
        query_index = end_of_current_query

    return transaction_id, flags, n_questions, n_answers, n_authrr, n_addrr, queries

# Apply filter and generate response from that
def generate_response( message: bytes ):

    tid, flags, nq, na, nauth, naddr, queries = parse_dns_message( message )
    for query in queries:
        domain, q_type, q_class = parse_query( query )
        if ( q_type == 1 or q_type == 28 ) and "ad" in domain:
            logger.log_info( f"Someone Asked For {domain} And It's Probably An Advertisement" )
            answer = create_answer( 12, 1, q_class, 2**16, b'\x11\x11\x11\x11' )
            flags = generate_flags( 1, 0, 0, 0, 1, 0, 0, 0 )
            message = create_dns_message( tid, flags, nq, b'\x00\x01', b'\x00\x00', b'\x00\x00', queries[ 0 ], answer )
            return message

    s = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
    s.sendto( message, ('8.8.8.8', 53) )
    return s.recvfrom( 512 )[ 0 ]

listener = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
listener.bind( ('', 53) )

while True:
    msg, addr = listener.recvfrom( 512 )
    listener.sendto( generate_response( msg ), addr )



